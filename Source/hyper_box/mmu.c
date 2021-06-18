/*
 *                   Hyper-Box of Alcatraz
 *                   ---------------------
 *      A Practical Hypervisor Sandbox to Prevent Escapes 
 *
 *               Copyright (C) 2021 Seunghun Han
 *             at The Affiliated Institute of ETRI
 */

/*
 * This software has GPL v2+ license. See the GPL_LICENSE file.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/rwlock_types.h>
#include <linux/reboot.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/version.h>
#include <asm/io.h>
#include "mmu.h"
#include "hyper_box.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
#include <linux/vmalloc.h>
#endif

/*
 * Variables.
 */
/*
 * Set buffer to protect Hyper-box data section from module structure.
 * 	Module structure is in front of data section and is not aligned by 4KB.
 */
char hb_dummy_buffer_for_4KB_align[0x2000] = {0, };
struct hb_ept_info g_ept_info = {0,};
static u64 g_ram_end;

/*
 * Functions.
 */
static void hb_set_ept_page_addr(u64 phy_addr, u64 addr);
static void hb_set_ept_page_flags(u64 phy_addr, u32 flags);
static int hb_callback_walk_ram(unsigned long start, unsigned long size,
	void* arg);
static int hb_callback_set_write_back_to_ram(unsigned long start,
	unsigned long size, void* arg);
static void hb_setup_ept_system_ram_range(void);
static int hb_alloc_ept_pages_internal(u64 *array, int count);
static void hb_free_ept_pages_internal(u64 *array, int count);

/*
 * Protect page table memory for EPT.
 */
void hb_protect_ept_pages(void)
{
	int i;
	u64 end;

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "Protect EPT\n");

	/* Hide the EPT page table */
	end = (u64)g_ept_info.pml4_page_addr_array + g_ept_info.pml4_page_count *
		sizeof(u64*);
	hb_hide_range((u64)g_ept_info.pml4_page_addr_array, end, ALLOC_VMALLOC);

	end = (u64)g_ept_info.pdpte_pd_page_addr_array +
		g_ept_info.pdpte_pd_page_count * sizeof(u64*);
	hb_hide_range((u64)g_ept_info.pdpte_pd_page_addr_array, end, ALLOC_VMALLOC);

	end = (u64)g_ept_info.pdept_page_addr_array +
		g_ept_info.pdept_page_count * sizeof(u64*);
	hb_hide_range((u64)g_ept_info.pdept_page_addr_array, end, ALLOC_VMALLOC);

	end = (u64)g_ept_info.pte_page_addr_array +
		g_ept_info.pte_page_count * sizeof(u64*);
	hb_hide_range((u64)g_ept_info.pte_page_addr_array, end, ALLOC_VMALLOC);

	for (i = 0 ; i < g_ept_info.pml4_page_count ; i++)
	{
		end = (u64)g_ept_info.pml4_page_addr_array[i] + EPT_PAGE_SIZE;
		hb_hide_range((u64)g_ept_info.pml4_page_addr_array[i], end,
			ALLOC_KMALLOC);
	}

	for (i = 0 ; i < g_ept_info.pdpte_pd_page_count ; i++)
	{
		end = (u64)g_ept_info.pdpte_pd_page_addr_array[i] + EPT_PAGE_SIZE;
		hb_hide_range((u64)g_ept_info.pdpte_pd_page_addr_array[i], end,
			ALLOC_KMALLOC);
	}

	for (i = 0 ; i < g_ept_info.pdept_page_count ; i++)
	{
		end = (u64)g_ept_info.pdept_page_addr_array[i] + EPT_PAGE_SIZE;
		hb_hide_range((u64)g_ept_info.pdept_page_addr_array[i], end,
			ALLOC_KMALLOC);
	}

	for (i = 0 ; i < g_ept_info.pte_page_count ; i++)
	{
		end = (u64)g_ept_info.pte_page_addr_array[i] + EPT_PAGE_SIZE;
		hb_hide_range((u64)g_ept_info.pte_page_addr_array[i], end,
			ALLOC_KMALLOC);
	}

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] Complete\n");
}

/*
 * Hide a physical page to protect it from the guest.
 */
void hb_set_ept_hide_page(u64 phy_addr)
{
	hb_set_ept_page_flags(phy_addr, EPT_BIT_MEM_TYPE_WB);
}

/*
 * Set read-only to a physical page to protect it from the guest.
 */
void hb_set_ept_read_only_page(u64 phy_addr)
{
	hb_set_ept_page_flags(phy_addr, EPT_READ | EPT_BIT_MEM_TYPE_WB);
	hb_set_ept_page_addr(phy_addr, phy_addr);
}

/*
 * Lock a physical page to protect it from the guest.
 */
void hb_set_ept_lock_page(u64 phy_addr)
{
	hb_set_ept_page_flags(phy_addr, EPT_READ | EPT_EXECUTE | EPT_BIT_MEM_TYPE_WB);
	hb_set_ept_page_addr(phy_addr, phy_addr);
}

/*
 * Set all permissions to a physcial page.
 */
void hb_set_ept_all_access_page(u64 phy_addr)
{
	hb_set_ept_page_flags(phy_addr, EPT_ALL_ACCESS | EPT_BIT_MEM_TYPE_WB);
	hb_set_ept_page_addr(phy_addr, phy_addr);
}

/*
 * Change physical address in EPT.
 */
static void hb_set_ept_page_addr(u64 phy_addr, u64 addr)
{
	u64 page_offset;
	u64* page_table_addr;
	u64 page_index;

	page_offset = phy_addr / EPT_PAGE_SIZE;
	page_index = page_offset % EPT_PAGE_ENT_COUNT;
	page_table_addr = hb_get_pagetable_log_addr(EPT_TYPE_PTE,
		page_offset / EPT_PAGE_ENT_COUNT);
	page_table_addr[page_index] = (addr & MASK_PAGEADDR) |
		(page_table_addr[page_index] & ~MASK_PAGEADDR);
}

/*
 * Set permissions to a physical page in EPT.
 */
static void hb_set_ept_page_flags(u64 phy_addr, u32 flags)
{
	u64 page_offset;
	u64* page_table_addr;
	u64 page_index;

	page_offset = phy_addr / EPT_PAGE_SIZE;
	page_index = page_offset % EPT_PAGE_ENT_COUNT;
	page_table_addr = hb_get_pagetable_log_addr(EPT_TYPE_PTE,
			page_offset / EPT_PAGE_ENT_COUNT);
	page_table_addr[page_index] = (page_table_addr[page_index] & MASK_PAGEADDR) |
		flags;
}

/*
 * Setup EPT.
 */
void hb_setup_ept_pagetable_4KB(void)
{
	struct hb_ept_pagetable* ept_info;
	u64 next_page_table_addr;
	u64 i;
	u64 j;
	u64 loop_cnt;
	u64 base_addr;

	/* Setup PML4. */
	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "Setup PLML4\n");
	ept_info = (struct hb_ept_pagetable*)hb_get_pagetable_log_addr(EPT_TYPE_PML4, 0);
	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Setup PML4 %016lX\n",
			(u64)ept_info);
	memset(ept_info, 0, sizeof(struct hb_ept_pagetable));

	/* Map all physical range. */
	for (i = 0 ; i < EPT_PAGE_ENT_COUNT ; i++)
	{
		next_page_table_addr = (u64)hb_get_pagetable_phy_addr(EPT_TYPE_PDPTEPD,
			i);
		ept_info->entry[i] = next_page_table_addr | EPT_ALL_ACCESS;

		if (i == 0)
		{
			hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] %016lX\n",
				(u64)next_page_table_addr);
		}
	}

	/* Setup PDPTE PD. */
	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "Setup PDPTEPD\n");
	base_addr = 0;
	for (j = 0 ; j < g_ept_info.pdpte_pd_page_count ; j++)
	{
		ept_info = (struct hb_ept_pagetable*)hb_get_pagetable_log_addr(EPT_TYPE_PDPTEPD,
			j);
		hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Setup PDPTEPD [%d] %016lX\n",
			j, (u64)ept_info);
		memset(ept_info, 0, sizeof(struct hb_ept_pagetable));

		/*
		 * Map 1:1 for all address spaces for IOMEM.
		 * 	Some devices have own IOMEM areas far from the RAM space.
		 */
		if (j * EPT_PAGE_ENT_COUNT > g_ept_info.pdpte_pd_ent_count)
		{
			for (i = 0 ; i < EPT_PAGE_ENT_COUNT ; i++)
			{
				ept_info->entry[i] = base_addr | EPT_ALL_ACCESS | MASK_PAGE_SIZE_FLAG | EPT_BIT_MEM_TYPE_WB;
				base_addr += VAL_1GB;
			}

			continue;
		}

		loop_cnt = g_ept_info.pdpte_pd_ent_count - (j * EPT_PAGE_ENT_COUNT);
		if (loop_cnt > EPT_PAGE_ENT_COUNT)
		{
			loop_cnt = EPT_PAGE_ENT_COUNT;
		}

		for (i = 0 ; i < EPT_PAGE_ENT_COUNT ; i++)
		{
			if (i < loop_cnt)
			{
				next_page_table_addr = (u64)hb_get_pagetable_phy_addr(EPT_TYPE_PDEPT,
					(j * EPT_PAGE_ENT_COUNT) + i);
				ept_info->entry[i] = next_page_table_addr | EPT_ALL_ACCESS;

				if (i == 0)
				{
					hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] %016lX\n",
						(u64)next_page_table_addr);
				}
			}
			else
			{
				ept_info->entry[i] = base_addr | EPT_ALL_ACCESS | MASK_PAGE_SIZE_FLAG | EPT_BIT_MEM_TYPE_WB;
			}

			base_addr += VAL_1GB;
		}
	}

	/* Setup PDEPT. */
	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "Setup PDEPT\n");
	base_addr = 0;
	for (j = 0 ; j < g_ept_info.pdept_page_count ; j++)
	{
		ept_info = (struct hb_ept_pagetable*)hb_get_pagetable_log_addr(EPT_TYPE_PDEPT,
			j);
		hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Setup PDEPT [%d] %016lX\n",
			j, (u64)ept_info);
		memset(ept_info, 0, sizeof(struct hb_ept_pagetable));

		loop_cnt = g_ept_info.pdept_ent_count - (j * EPT_PAGE_ENT_COUNT);
		if (loop_cnt > EPT_PAGE_ENT_COUNT)
		{
			loop_cnt = EPT_PAGE_ENT_COUNT;
		}

		for (i = 0 ; i < EPT_PAGE_ENT_COUNT ; i++)
		{
			if (i < loop_cnt)
			{
				next_page_table_addr = (u64)hb_get_pagetable_phy_addr(EPT_TYPE_PTE,
					(j * EPT_PAGE_ENT_COUNT) + i);
				ept_info->entry[i] = next_page_table_addr | EPT_ALL_ACCESS;

				if (i == 0)
				{
					hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] %016lX\n",
						(u64)next_page_table_addr);
				}
			}
			else
			{
				ept_info->entry[i] = base_addr | EPT_ALL_ACCESS | MASK_PAGE_SIZE_FLAG | EPT_BIT_MEM_TYPE_WB;
			}

			base_addr += VAL_2MB;
		}
	}

	/* Setup PTE. */
	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "Setup PTE\n");
	for (j = 0 ; j < g_ept_info.pte_page_count ; j++)
	{
		ept_info = (struct hb_ept_pagetable*)hb_get_pagetable_log_addr(EPT_TYPE_PTE,
			j);
		memset(ept_info, 0, sizeof(struct hb_ept_pagetable));

		for (i = 0 ; i < EPT_PAGE_ENT_COUNT ; i++)
		{
			next_page_table_addr = ((u64)j * EPT_PAGE_ENT_COUNT + i) *
				EPT_PAGE_SIZE;
			/*
			 * Set uncacheable type by default.
			 * Set write-back type to "System RAM" areas at the end of this
			 * function.
			 */
			ept_info->entry[i] = next_page_table_addr | EPT_ALL_ACCESS | EPT_BIT_MEM_TYPE_WB;
		}
	}

	/* Set write-back type to "System RAM" areas. */
	hb_setup_ept_system_ram_range();
}

/*
 *	Allocate pages for EPT internally.
 */
static int hb_alloc_ept_pages_internal(u64 *array, int count)
{
	int i;

	for (i = 0 ; i < count ; i++)
	{
		array[i] = (u64)__get_free_page(GFP_KERNEL);
		if (array[i] == 0)
		{
			return -1;
		}
	}
	return 0;
}

/*
 * Free pages for EPT internally.
 */
static void hb_free_ept_pages_internal(u64 *array, int count)
{
	int i;

	for (i = 0 ; i < count ; i++)
	{
		if (array[i] != 0)
		{
			free_page(array[i]);
		}
	}
}

/*
 * Allocate memory for EPT.
 */
int hb_alloc_ept_pages(void)
{
	g_ept_info.pml4_ent_count = CEIL(g_max_ram_size, VAL_512GB);
	g_ept_info.pdpte_pd_ent_count = CEIL(g_max_ram_size, VAL_1GB);
	g_ept_info.pdept_ent_count = CEIL(g_max_ram_size, VAL_2MB);
	g_ept_info.pte_ent_count = CEIL(g_max_ram_size, VAL_4KB);

	g_ept_info.pml4_page_count = PML4_PAGE_COUNT;
	g_ept_info.pdpte_pd_page_count = EPT_PAGE_ENT_COUNT;
	g_ept_info.pdept_page_count = CEIL(g_ept_info.pdept_ent_count, EPT_PAGE_ENT_COUNT);
	g_ept_info.pte_page_count = CEIL(g_ept_info.pte_ent_count, EPT_PAGE_ENT_COUNT);

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "Setup EPT, Max RAM Size %ld\n",
		g_max_ram_size);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] EPT Size: %d\n",
		(int)sizeof(struct hb_ept_pagetable));
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] PML4 Entry Count: %d\n",
		(int)g_ept_info.pml4_ent_count);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] PDPTE PD Entry Count: %d\n",
		(int)g_ept_info.pdpte_pd_ent_count);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] PDE PT Entry Count: %d\n",
		(int)g_ept_info.pdept_ent_count);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] PTE Entry Count: %d\n",
		(int)g_ept_info.pte_ent_count);

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] PML4 Page Count: %d\n",
		(int)g_ept_info.pml4_page_count);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] PDPTE PD Page Count: %d\n",
		(int)g_ept_info.pdpte_pd_page_count);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] PDE PT Page Count: %d\n",
		(int)g_ept_info.pdept_page_count);
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] PTE Page Count: %d\n",
		(int)g_ept_info.pte_page_count);

	/* Allocate memory for page table. */
	g_ept_info.pml4_page_addr_array = (u64*)vzalloc(g_ept_info.pml4_page_count *
		sizeof(u64*));
	g_ept_info.pdpte_pd_page_addr_array = (u64*)vzalloc(g_ept_info.pdpte_pd_page_count *
		sizeof(u64*));
	g_ept_info.pdept_page_addr_array = (u64*)vzalloc(g_ept_info.pdept_page_count *
		sizeof(u64*));
	g_ept_info.pte_page_addr_array = (u64*)vzalloc(g_ept_info.pte_page_count *
		sizeof(u64*));

	if ((g_ept_info.pml4_page_addr_array == NULL) ||
		(g_ept_info.pdpte_pd_page_addr_array == NULL) ||
		(g_ept_info.pdept_page_addr_array == NULL) ||
		(g_ept_info.pte_page_addr_array == NULL))
	{
		goto ERROR;
	}

	if (hb_alloc_ept_pages_internal(g_ept_info.pml4_page_addr_array,
		g_ept_info.pml4_page_count) != 0)
	{
		goto ERROR;
	}

	if (hb_alloc_ept_pages_internal(g_ept_info.pdpte_pd_page_addr_array,
		g_ept_info.pdpte_pd_page_count) != 0)
	{
		goto ERROR;
	}

	if (hb_alloc_ept_pages_internal(g_ept_info.pdept_page_addr_array,
		g_ept_info.pdept_page_count) != 0)
	{
		goto ERROR;
	}

	if (hb_alloc_ept_pages_internal(g_ept_info.pte_page_addr_array,
		g_ept_info.pte_page_count) != 0)
	{
		goto ERROR;
	}

	hb_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Page Table Memory Alloc Success\n");

	return 0;

ERROR:
	hb_printf(LOG_LEVEL_ERROR, LOG_INFO " hb_alloc_ept_pages alloc fail\n");

	return -1;
}

/*
 * Free allocated memory for EPT.
 */
void hb_free_ept_pages(void)
{
	if (g_ept_info.pml4_page_addr_array != 0)
	{
		hb_free_ept_pages_internal(g_ept_info.pml4_page_addr_array,
			g_ept_info.pml4_page_count);

		vfree(g_ept_info.pml4_page_addr_array);
		g_ept_info.pml4_page_addr_array = 0;
	}

	if (g_ept_info.pdpte_pd_page_addr_array != 0)
	{
		hb_free_ept_pages_internal(g_ept_info.pdpte_pd_page_addr_array,
			g_ept_info.pdpte_pd_page_count);

		vfree(g_ept_info.pdpte_pd_page_addr_array);
		g_ept_info.pdpte_pd_page_addr_array = 0;
	}

	if (g_ept_info.pdept_page_addr_array != 0)
	{
		hb_free_ept_pages_internal(g_ept_info.pdept_page_addr_array,
			g_ept_info.pdept_page_count);

		vfree(g_ept_info.pdept_page_addr_array);
		g_ept_info.pdept_page_addr_array = 0;
	}

	if (g_ept_info.pte_page_addr_array != 0)
	{
		hb_free_ept_pages_internal(g_ept_info.pte_page_addr_array,
			g_ept_info.pte_page_count);

		vfree(g_ept_info.pte_page_addr_array);
		g_ept_info.pte_page_addr_array = 0;
	}
}

/*
 * Process callback of walk_system_ram_range().
 *
 * This function sets write-back cache type to EPT page.
 */
static int hb_callback_set_write_back_to_ram(unsigned long start,
	unsigned long size, void* arg)
{
	struct hb_ept_pagetable* ept_info;
	unsigned long i;

	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "System RAM start %016lX, end %016lX, "
		"size %016lX\n", start * PAGE_SIZE, start * PAGE_SIZE + size * PAGE_SIZE,
		size * PAGE_SIZE);

	for (i = start ; i < start + size ; i++)
	{
		ept_info = (struct hb_ept_pagetable*)hb_get_pagetable_log_addr(EPT_TYPE_PTE,
			i / EPT_PAGE_ENT_COUNT);
		ept_info->entry[i %  EPT_PAGE_ENT_COUNT] |= EPT_BIT_MEM_TYPE_WB;
	}

	return 0;
}

/*
 * Set write-back permission to System RAM area.
 */
static void hb_setup_ept_system_ram_range(void)
{
	my_walk_system_ram_range func = NULL;

	func = (my_walk_system_ram_range)hb_get_symbol_address("walk_system_ram_range");
	if (func == NULL)
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "walk_system_ram_range fail\n");
		return ;
	}

	func(0, g_max_ram_size / PAGE_SIZE, NULL, hb_callback_set_write_back_to_ram);
}


/*
 * Process callback of walk_system_ram_range().
 *
 * This function adds the end of system RAM.
 */
static int hb_callback_walk_ram(unsigned long start, unsigned long size, void* arg)
{
	hb_printf(LOG_LEVEL_DEBUG, LOG_INFO "System RAM start %016lX, end %016lX, "
		"size %016lX\n", start * PAGE_SIZE, start * PAGE_SIZE + size * PAGE_SIZE,
		size * PAGE_SIZE);

	if (g_ram_end < ((start + size) * PAGE_SIZE))
	{
		g_ram_end = (start + size) * PAGE_SIZE;
	}

	return 0;
}

/*
 * Calculate System RAM size.
 */
u64 hb_get_max_ram_size(void)
{
	my_walk_system_ram_range func = NULL;
	u64 total_pages;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
	total_pages = totalram_pages;
#else /* LINUX_VERSION_CODE */
	total_pages = totalram_pages();
#endif /* LINUX_VERSION_CODE */

	g_ram_end = 0;

	func = (my_walk_system_ram_range)hb_get_symbol_address("walk_system_ram_range");
	if (func == NULL)
	{
		hb_printf(LOG_LEVEL_ERROR, LOG_INFO "walk_system_ram_range fail\n");
		return total_pages * 2 * VAL_4KB;
	}

	func(0, total_pages * 2, NULL, hb_callback_walk_ram);

	return g_ram_end;
}

/*
 * Get logical address of page table pointer of index and type.
 */
void* hb_get_pagetable_log_addr(int type, int index)
{
	u64* table_array_addr;

	switch(type)
	{
	case EPT_TYPE_PML4:
		table_array_addr = g_ept_info.pml4_page_addr_array;
		break;

	case EPT_TYPE_PDPTEPD:
		table_array_addr = g_ept_info.pdpte_pd_page_addr_array;
		break;

	case EPT_TYPE_PDEPT:
		table_array_addr = g_ept_info.pdept_page_addr_array;
		break;

	case EPT_TYPE_PTE:
	default:
		table_array_addr = g_ept_info.pte_page_addr_array;
		break;
	}

	return (void*)table_array_addr[index];
}

/*
 * Get physical address of page table pointer of index and type.
 */
void* hb_get_pagetable_phy_addr(int type, int index)
{
	void* table_log_addr;

	table_log_addr = hb_get_pagetable_log_addr(type, index);
	return (void*)virt_to_phys(table_log_addr);
}
