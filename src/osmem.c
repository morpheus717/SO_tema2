// SPDX-License-Identifier: BSD-3-Clause

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <assert.h>
#include <string.h>

#include <block_meta.h>

#define BL_SIZ sizeof(struct block_meta)
#define MMAP_THRESH (128 * 1024)
#define PADDING compute_padding(sizeof(block_meta))
#define PADDED_BL (BL_SIZ + PADDING)

typedef struct block_meta block_meta;

block_meta *global_base;
int preallocated;

int compute_padding(int num)
{
	int aux = num;

	while (aux % 8 != 0)
		aux++;
	return aux - num;
}

/**
 * @brief Provided with a node, it will return the last node of its list
 *
 * @return block_meta* last node of the list
 */
block_meta *find_last(block_meta *start)
{
	if (!start)
		return NULL;
	while (start->next)
		start = start->next;
	return start;
}

block_meta *request_space_sbrk(block_meta *last, size_t size)
{
	last = find_last(last);
	int aux;

	if (size == MMAP_THRESH)
		aux = size;
	else
		aux = size + PADDED_BL + compute_padding(size);
	block_meta *new = sbrk(aux);

	DIE((void *)new == (void *)(-1), "sbrk error");
	new->status = STATUS_ALLOC;
	new->size = size + compute_padding(size);
	new->next = NULL;
	new->prev = last;
	if (last)
		last->next = new;
	return new;
}

/**
 * @brief Merges nodes first and first->next
 *
 * @return block_meta* NULL if failed, first otherwise
 */
block_meta *merge_adjacent(block_meta *first)
{
	block_meta *second = first->next;

	if (!(second->status == STATUS_FREE && first->status == STATUS_FREE))
		return NULL;
	first->next = second->next;
	if (second->next)
		second->next->prev = first;
	first->size += compute_padding(first->size) + PADDED_BL + second->size + compute_padding(second->size);
	return first;
}

/**
 * @brief Extends the last node of the list by size bytes
 *
 * @param start any node of the list
 * @param size required size
 * @return block_meta* address of the last node
 */
block_meta *extend_last(block_meta *start, size_t size)
{
	start = find_last(start);
	DIE(!start, "You're not supposed to be here!");
	if (start->status != STATUS_FREE)
		return NULL;
	int extension = size - start->size - compute_padding(start->size);

	extension += compute_padding(extension);
	sbrk(extension);
	start->size = size;
	start->status = STATUS_ALLOC;
	return start;
}

block_meta *request_space_mmap(block_meta *last, size_t size)
{
	last = find_last(last);
	block_meta *new = mmap(NULL, size + BL_SIZ + PADDING + compute_padding(size),
					 PROT_READ | PROT_WRITE, MAP_PRIVATE | 0x20, -1, 0);
	DIE(new == MAP_FAILED, "mmap error");
	new->status = STATUS_MAPPED;
	new->size = size + BL_SIZ + PADDING + compute_padding(size);
	new->next = NULL;
	new->prev = last;
	if (last)
		last->next = new;
	return new;
}

/**
 * @brief Fragments a block
 *
 * @param block the block to be fragmented
 * @param size the size needed for the first block
 * @return block_meta* the first block that is now allocated
 */
block_meta *fragment_block(block_meta *block, size_t size)
{
	char *aux = (char *)block + PADDED_BL + size + compute_padding(size);
	block_meta *new = (block_meta *)aux;

	new->size = block->size + compute_padding(block->size) - size - compute_padding(size) - PADDED_BL;
	new->prev = block;
	new->next = block->next;
	if (block->next)
		block->next->prev = new;
	block->next = new;
	new->status = STATUS_FREE;
	block->size = size;
	block->status = STATUS_ALLOC;
	return block;
}

/**
 * @brief finds a free block whose size is nearest to the one required
 *
 * @param last first node of the list
 * @param size the size required
 * @return block_meta* found block, NULL if it does not exist
 */
block_meta *find_free_block(size_t size)
{
	block_meta *first = global_base;

	if (!first)
		return NULL;
	block_meta *best = NULL;
	int min_diff = __INT_MAX__;

	while (first) {
		int diff = first->size + compute_padding(first->size) - size;

		if (first->status == STATUS_FREE && diff < min_diff && diff >= 0) {
			min_diff = diff;
			best = first;
		}
		first = first->next;
	}
	if (best && best->size + compute_padding(best->size) > size + compute_padding(size) + PADDED_BL)
		fragment_block(best, size);
	return best;
}

void coalesce_all(block_meta *start)
{
	if (!start)
		return;
	block_meta *aux = start;

	while (aux->next) {
		if (!merge_adjacent(aux))
			aux = aux->next;
	}
}

/**
 * @brief Decides whether to allocate using sbrk or mmap
 *
 * @param last Function will allocate at the end of the list regardless of its value
 * @param size Needed bytes
 * @return block_meta*
 */
block_meta *request_space(block_meta *last, size_t size)
{
	last = find_last(last);
	block_meta *requested;

	if (size + PADDED_BL + compute_padding(size) > MMAP_THRESH) {
		requested = request_space_mmap(last, size);
	} else {
		coalesce_all(global_base);
		block_meta *best = find_free_block(size);

		if (best) {
			best->size = size;
			best->status = STATUS_ALLOC;
			requested = best;
		} else if (last && last->status == STATUS_FREE) {
			requested = extend_last(last, size);
		} else if (!preallocated) {
			preallocated++;
			requested = request_space_sbrk(last, MMAP_THRESH);
			requested->size = size;
		} else {
			requested = request_space_sbrk(last, size);
		}
	}
	if (!global_base)
		global_base = requested;
	return requested;
}

int unmap_block(block_meta *block)
{
	if (block->next)
		block->next->prev = block->prev;
	if (block->prev)
		block->prev->next = block->next;
	if (block == global_base) {
		global_base = global_base->next;
		if (global_base)
			global_base->prev = NULL;
	}
	return munmap(block, block->size);
}

void *os_malloc(size_t size)
{
	/* TODO: Implement os_malloc */
	if (!size)
		return NULL;
	return (char *)request_space(global_base, size) + PADDED_BL;
}

void os_free(void *ptr)
{
	/* TODO: Implement os_free */
	if (!ptr)
		return;
	block_meta *node = global_base;

	DIE(!node, "Invalid free");
	while (node) {
		block_meta *aux = node + 1;

		if ((void *)aux == ptr)
			break;
		node = node->next;
	}
	DIE(!node, "Invalid free");
	if (node->status == STATUS_MAPPED) {
		unmap_block(node);
		return;
	}
	if (node->status == STATUS_ALLOC) {
		node->status = STATUS_FREE;
		coalesce_all(global_base);
		return;
	}
	DIE(1, "DOUBLE FREE!!!");
}

block_meta *request_space_calloc(block_meta *last, size_t size)
{
	last = find_last(last);
	block_meta *requested;

	if (size + PADDED_BL + compute_padding(size) > (size_t)getpagesize()) {
		requested = request_space_mmap(last, size);
	} else {
		coalesce_all(global_base);
		block_meta *best = find_free_block(size);

		if (best) {
			best->size = size;
			best->status = STATUS_ALLOC;
			requested = best;
		} else if (last && last->status == STATUS_FREE) {
			requested = extend_last(last, size);
		} else if (!preallocated) {
			preallocated++;
			requested = request_space_sbrk(last, MMAP_THRESH);
			requested->size = size;
		} else {
			requested = request_space_sbrk(last, size);
		}
	}
	if (!global_base)
		global_base = requested;
	return requested;
}

void *os_calloc(size_t nmemb, size_t size)
{
	/* TODO: Implement os_calloc */
	if (!nmemb || !size)
		return NULL;
	void *allocated = request_space_calloc(global_base, size * nmemb) + 1;

	memset(allocated, 0, nmemb * size);
	return allocated;
}

size_t min_size(size_t size1, size_t size2)
{
	if (size1 > size2)
		return size2;
	return size1;
}

void *os_realloc(void *ptr, size_t size)
{
	/* TODO: Implement os_realloc */
	if (!ptr)
		return os_malloc(size);
	if (!size) {
		os_free(ptr);
		return NULL;
	}
	block_meta *block = (block_meta *)((char *)ptr - PADDED_BL);

	if (block->status == STATUS_MAPPED) {
		void *newptr = os_malloc(size);

		memcpy(newptr, ptr, min_size(size, block->size));
		os_free(ptr);
		return newptr;
	}
	if (block->status == STATUS_FREE)
		return NULL;
	if (block->size > size) {
		if (block->size + compute_padding(block->size) > size + compute_padding(size) + PADDED_BL)
			return fragment_block(block, size) + 1;
		return ptr;
	} else if (block->size < size) {
		if (!block->next) {
			block = extend_last(block, size);
			return ptr;
		}
		coalesce_all(global_base);
		if (block->next && block->next->status == STATUS_FREE && block->size
			+ block->next->size + PADDED_BL >= size + compute_padding(size)) {
			block->status = STATUS_FREE;
			block = merge_adjacent(block);
			block->status = STATUS_ALLOC;
			if (block->size > size + compute_padding(size) + PADDED_BL)
				block = fragment_block(block, size);
			return ptr;
		}
		void *newptr = os_malloc(size);

		memcpy(newptr, ptr, block->size);
		os_free(ptr);
		return newptr;
	}
	return ptr;
}
