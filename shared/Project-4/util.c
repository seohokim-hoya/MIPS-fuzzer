/* util.c

********** DO NOT CHANGE THIS FILE ***********

*/


#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // for getopt()

#include "util.h"

// number of maximum page tables: 1 base page table + 1024 page table nodes
#define MAX_PAGE_TABLES 1025
#define MAX_PAGES 1024 * 1024

// allocated memory space for base page table & page table nodes
static uint32_t *emulated_memory;
// address for new page table nodes
static addr_t next_free_PT_node_addr = 0x0U;
// address for new page
static addr_t next_free_page_addr = 0x401000U;
// page table base register value, fixed
static addr_t page_table_base_reg = 0;
// number of allocated pages
static uint32_t num_allocated_pages = 1025;

/**
 * @brief Read 4 byte data from page table
 * 
 * @param addr physical address of the data to read
 * @return uint32_t 4 byte data from that address
 */
uint32_t mem_read_word32 (addr_t addr) {
	return emulated_memory[addr >> 2];
}
/**
 * @brief Write a 4 byte data to page table
 * 
 * @param addr physical address of the data to write
 * @param value 4 byte data to write
 */
void  mem_write_word32 (addr_t addr, uint32_t value) {
	emulated_memory[addr >> 2] = value;
}
/**
 * @brief Initialize the internal emulated memory and 1st-level page table node.
 * The 1st-level page table node (4KB) is created during the initialization,
 * so you must not create one for yourself.
 */
void init() {
	// allocate page table nodes and initialize all values to 0
	emulated_memory = (uint32_t *)calloc(1024*MAX_PAGE_TABLES, sizeof(unsigned int));

	// If allocation fails, abort
 	if (!emulated_memory) {
		fprintf(stderr, "cannot allocated emulated memory\n");
		exit (1);

	}

	// set base register to the physical address of base page table
	page_table_base_reg = get_new_page_table_node();
}
/**
 * @brief Get the address of base page table
 * 
 * @return addr_t address of the base page table
 */
addr_t page_table_base_addr() {
	return page_table_base_reg;
}

/**
 * @brief Returns the address of a new page table node.
 * This function must be called to get a new page table node
 * for 2nd-level page table node if it is required to handle a page fault. 
 * 
 * @return addr_t address of the page table node
 */
addr_t get_new_page_table_node() {
	int i;
	// address of new allocated page table node
	addr_t free_pt_node = next_free_PT_node_addr;

	// If we cannot allocate new page table node, abort
	if ((next_free_PT_node_addr >> 12) >= MAX_PAGE_TABLES) {
		fprintf(stderr, "PAGE TABLE IS FULL\n");
		exit(0);
	}

	// increase the free page table node stack
	next_free_PT_node_addr += 4096;

	// clear all data in the page table node
	for(i = 0; i < 4096; i = i + 4)
		mem_write_word32(free_pt_node + i, 0U);

	return free_pt_node;
}
/**
 * @brief Returns the address of a new 4KB page.
 * This function must be called to get a new physical 4KB memory to handle
 * a page fault. To get the address of a page table node, you must use
 * the following function: get_new_page_table_node().
 * 
 * @return addr_t address of the physical page
 */
addr_t get_new_physical_page() {
	// check whether it is possible to allocate new pages
	if(num_allocated_pages >= MAX_PAGES)
	{
		fprintf(stderr, "ALL PAGES ARE ALLOCATED\n");
		exit(0);
	}

	// set the new page physical address
	addr_t free_page_addr = next_free_page_addr;  
	// increase the free page stack
	next_free_page_addr += 4096;
	// count new page allocation
	num_allocated_pages++;

	return free_page_addr;
}
/**
 * @brief It writes the contents of the page table to a file whose name is fixed to
 * “page_table_dump”. This function must be used to dump the page table content for
 * “-x” option.
 */
void dump_page_table_area() 
{
	FILE *fp;
	unsigned int i, j, k;
	// Try to make a file "page_table_dump"
	fp = fopen("page_table_dump", "w"); // open dump file
	if(fp == NULL){
		printf("\nCannot open page table dump file: \n");
		return;
	}

	fprintf(fp, "Base Page Table Contents:\n");
	// print all entries in base page table
	for(i = 0; i < 4096; i += 32) {
		// print 8 entries in base page table
		for(j = i; j < i + 32; j += 4) {
			uint32_t content = mem_read_word32(j);
			fprintf(fp, "%08x ", content);
		}
		fprintf(fp, "\n");
	}
	fprintf(fp, "\n");

	fprintf(fp, "Page Table Node Contents:\n");
	// print all entries in allocated page table nodes
	for(i = 4096; i < next_free_PT_node_addr; i += 4096) {
		fprintf(fp, "%dth page table nodes:\n", (i >> 12));

		// print all entries in a page table node
		for(j = i; j < i + 4096; j += 32) {
			// print 8 entries in a page table node
			for(k = j; k < j + 32; k += 4) {
				uint32_t content = mem_read_word32(k);
				fprintf(fp, "%08x ", content);
			}
			fprintf(fp, "\n");
		}
		fprintf(fp, "\n");
	}

	// close the "page_table_dump" file
	fclose (fp);
}


/***************************************************************/
/*                                                             */
/* Procedure : cdump                                           */
/*                                                             */
/* Purpose   : Dump TLB configuration                        */
/*                                                             */
/***************************************************************/
void cdump(int n_entries, int assoc) {
        printf("TLB Configuration:\n");
        printf("-------------------------------------\n");
        printf("Number of entries: %d\n", n_entries);
        printf("Associativity: %dway\n", assoc);
        printf("\n");
}

/***************************************************************/
/*                                                             */
/* Procedure : sdump                                           */
/*                                                             */
/* Purpose   : Dump TLB stat                                   */
/*                                                             */
/***************************************************************/
void sdump(int total_accesses, int reads, int writes, int tlb_accesses,
	int tlb_hits, int tlb_misses, int page_walks, int page_faults) {
        printf("MMU Stats:\n");
        printf("-------------------------------------\n");
        printf("Total memory accesses: %d\n", total_accesses);
		printf("Total read accesses: %d\n", reads);
		printf("Total write accesses: %d\n", writes);
		printf("Total TLB accesses: %d\n", tlb_accesses);
        printf("Total TLB hits: %d\n", tlb_hits);
        printf("Total TLB misses: %d\n", tlb_misses);
		printf("Total page walks: %d\n", page_walks);
        printf("Total page faults: %d\n", page_faults);
        printf("\n");
}



