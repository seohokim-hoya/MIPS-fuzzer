/* util.h

********** DO NOT CHANGE THIS FILE ***********

*/



#ifndef __UTIL_H_
#define __UTIL_H_

#include <stdint.h>

// redefinition of address type
typedef uint32_t addr_t;

/**
 * @brief Read 4 byte data from page table
 * 
 * @param addr physical address of the data to read
 * @return uint32_t 4 byte data from that address
 */
uint32_t mem_read_word32 (addr_t addr);
/**
 * @brief Write a 4 byte data to page table
 * 
 * @param addr physical address of the data to write
 * @param value 4 byte data to write
 */
void  mem_write_word32 (addr_t addr, uint32_t value);

/**
 * @brief Initialize the internal emulated memory and 1st-level page table node.
 * The 1st-level page table node (4KB) is created during the initialization,
 * so you must not create one for yourself.
 */
void init();

/**
 * @brief Get the address of base page table
 * 
 * @return addr_t address of the base page table
 */
addr_t page_table_base_addr();

/**
 * @brief Returns the address of a new page table node.
 * This function must be called to get a new page table node
 * for 2nd-level page table node if it is required to handle a page fault. 
 * 
 * @return addr_t address of the page table node
 */
addr_t get_new_page_table_node();

/**
 * @brief Returns the address of a new 4KB page.
 * This function must be called to get a new physical 4KB memory to handle
 * a page fault. To get the address of a page table node, you must use
 * the following function: get_new_page_table_node().
 * 
 * @return addr_t address of the physical page
 */
addr_t get_new_physical_page();

/**
 * @brief It writes the contents of the page table to a file whose name is fixed to
 * “page_table_dump”. This function must be used to dump the page table content for
 * “-x” option.
 */
void dump_page_table_area();

/**
 * @brief Print out the configuration of MMU
 * 
 * @param n_entries number of entries of the TLB
 * @param assoc number of associativity of the TLB
 */
void cdump(int n_entries, int assoc);

/**
 * @brief Print out the run statistics.
 * 
 * @param total_accesses number of memory accesses
 * @param reads number of read memory accesses
 * @param writes number of write memory accesses
 * @param tlb_accesses number of TLB accesses
 * @param total_hits number of TLB hits
 * @param total_misses number of TLB misses
 * @param page_walks number of page table walks by page table walker
 * @param total_page_faults number of page faults
 */
void sdump(int total_accesses, int reads, int writes, int tlb_accesses,
	int tlb_hits, int tlb_misses, int page_walks, int page_faults);




#endif
