#include <intrinsics.hpp>

#define printf(Format, ...) NtImports::fn_DbgPrintEx(0, 0, Format, __VA_ARGS__)

const char* GetRegionName(UINT32 type)
{
	switch (type)
	{
	case AssignedRegionPfnDatabase:          return "PfnDatabase";
	case AssignedRegionNonPagedPool:         return "NonPagedPool";
	case AssignedRegionPagedPool:            return "PagedPool";
	case AssignedRegionSystemCache:          return "SystemCache";
	case AssignedRegionSystemPtes:           return "SystemPtes";
	case AssignedRegionKasan:                return "Kasan";
	case AssignedRegionUltraZero:            return "UltraZero";
	case AssignedRegionCfg:                  return "Cfg";
	case AssignedRegionHyperSpace:           return "HyperSpace";
	case AssignedRegionKernelStacks:         return "KernelStacks";
	case AssignedRegionNonCachedMappings:    return "NonCachedMappings";
	case AssignedRegionSoftWsles:            return "SoftWsles";
	case AssignedRegionPageTables:           return "PageTables";
	case AssignedRegionNotUsed:              return "NotUsed";
	case AssignedRegionSecureNonPagedPool:   return "SecureNonPagedPool";
	case AssignedRegionKernelShadowStacks:   return "KernelShadowStacks";
	case AssignedRegionSystemDataViews:      return "SystemDataViews";
	case AssignedRegionSystemImages:         return "SystemImages";
	case AssignedRegionMaximum:              return "Maximum";

	default:                                 return "Unknown";
	}
}

BOOLEAN ValidateTranslation(PHYSICAL_ADDRESS page)
{
	auto PfnDatabase = MmPfnDatabase();
	auto RegionDatabase = (_MI_ASSIGNED_REGION_TYPES*)MiSystemRegionTypeDatabase();

	auto PteAddress = (LINEAR_ADDRESS)PfnDatabase[page >> PAGE_SHIFT].PteAddress;
	if (PteAddress.pml4e_index <= 256)
		return false;// usermode pte will miss identify page as normal

	auto type = RegionDatabase[PteAddress.pml4e_index - 256];
	if (type != AssignedRegionSystemCache)
		return false;// pfn page is not marked as system cache

	return true;
}


void ValidateUsermodePageMapping(PEPROCESS eproc)
{
	SIZE_T bytes_copied = 0;
	KAPC_STATE apc;

	auto dtb = *(UINT64*)((UINT64)eproc + 0x28) & ~0xFFF;

	KeStackAttachProcess(eproc, &apc);

	auto pml4_pa = dtb;
	if (!ValidateTranslation(pml4_pa))
		printf("[PID 0x%08X] PfnDatabase validation failed! PML4\n", PsGetProcessId(eproc));
	auto pml4 = (MMPTE_HARDWARE*)MmGetVirtualForPhysical(pml4_pa);
	for (int l1 = 0; l1 < 256; l1++)
	{
		if (pml4[l1].Valid)
		{
			auto pdpt_pa = pml4[l1].PageFrameNumber << PAGE_SHIFT;
			if (!ValidateTranslation(pdpt_pa))
				printf("[PID 0x%08X] PfnDatabase validation failed! PDPT\n", PsGetProcessId(eproc));
			auto pdpt = (MMPTE_HARDWARE*)MmGetVirtualForPhysical(pdpt_pa);
			for (int l2 = 0; l2 < 512; l2++)
			{
				if (pdpt[l2].Valid)
				{
					auto pdt_pa = pdpt[l2].PageFrameNumber << PAGE_SHIFT;
					if (!ValidateTranslation(pdt_pa))
						printf("[PID 0x%08X] PfnDatabase validation failed! PDT\n", PsGetProcessId(eproc));
					auto pdt = (MMPTE_HARDWARE*)MmGetVirtualForPhysical(pdt_pa);
					for (int l3 = 0; l3 < 512; l3++)
					{
						if (pdt[l3].Valid)
						{
							auto pte_pa = pdt[l3].PageFrameNumber << PAGE_SHIFT;
							if (!ValidateTranslation(pte_pa))
								printf("[PID 0x%08X] PfnDatabase validation failed! PTE\n", PsGetProcessId(eproc));
							auto pte = (MMPTE_HARDWARE*)MmGetVirtualForPhysical(pte_pa);
							for (int l4 = 0; l4 < 512; l4++)
							{
								if (pte[l4].Valid)
								{
									LINEAR_ADDRESS leaf_pfn = MmGetVirtualForPhysical(pte[l4].PageFrameNumber << PAGE_SHIFT);
									auto type = MiGetSystemRegionType(leaf_pfn.AsPointer);

									if (type)
									{
										LINEAR_ADDRESS rva;
										rva.AsUINT64 = 0;
										rva.pml4e_index = l1;
										rva.pdpte_index = l2;
										rva.pde_index = l3;
										rva.pte_index = l4;

										switch (type)
										{
										case 4:
										{
											printf("Sessioned PID 0x%08X [ RVA: %p | PFN: %010LLX ] -> type: %s (you should never see this)\n",
												PsGetProcessId(eproc), rva.AsUINT64, pte[l4].PageFrameNumber, GetRegionName(type));
										}break;
										default:
										{
											printf("Sessioned PID 0x%08X [ RVA: %p | PFN: %010LLX ] -> type: %s (normal)\n",
												PsGetProcessId(eproc), rva.AsUINT64, pte[l4].PageFrameNumber, GetRegionName(type));
											break;
										}
										}

									}
								}
							}
						}
					}
				}
			}
		}
	}
	KeUnstackDetachProcess(&apc);
}

void ScanEProcess()
{
	auto MHz = MSR::PSTATE(0).get_frequency_mhz();
	auto tsc_start = MSR::TSC();
	auto flink = (UINT64)PsInitialSystemProcess();
	auto o_UniqueProcessId = *(UINT32*)((UINT64)NtImports::fn_PsGetProcessId + 0x3);// fix for 22H2 & 24H2
	do
	{
		if (PsGetProcessId((PEPROCESS)flink) != 4)
		{
			auto PEB = *(QWORD*)(flink + o_UniqueProcessId + 0x110);
			if (PEB)
			{
				ValidateUsermodePageMapping((PEPROCESS)flink);
			}
		}
		flink = *(UINT64*)((UINT64)flink + o_UniqueProcessId + 0x8) - (o_UniqueProcessId + 0x8);
	} while (flink != (UINT64)PsInitialSystemProcess());
	double mutiplier = (double)(MSR::TSC() - tsc_start) / (double)MHz;
	auto Ms = (UINT64)(mutiplier * 1000.0);
	printf("Usermode pte scan completed in %llu ms\n", Ms);
	return;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	auto RegionDatabase = (_MI_ASSIGNED_REGION_TYPES*)MiSystemRegionTypeDatabase();

	for (int i = 0; i < 255; i++)
	{
		if (RegionDatabase[i] == AssignedRegionSystemCache)
		{
			LINEAR_ADDRESS rva;
			rva.AsUINT64 = 0xFFFF000000000000;
			rva.pml4e_index = i + 256;

			for (int lv2 = 0; lv2 < 512; lv2++)
			{
				for (int lv3 = 0; lv3 < 512; lv3++)
				{
					for (int lv4 = 0; lv4 < 512; lv4++)
					{
						rva.pdpte_index = lv2;
						rva.pde_index = lv3;
						rva.pte_index = lv4;
						auto pa = MmGetPhysicalAddress(rva.AsPointer);
						if (pa)
						{
							auto va = MmGetVirtualForPhysical(pa);
							auto type = MiGetSystemRegionType(va);
							
							if (type && type != AssignedRegionSystemCache)
							{
								printf("%s", GetRegionName(type));
								printf(" - Subpage found at RVA: %p %i %i %i [ PFN: %010LLX ]\n", rva.AsUINT64, rva.pdpte_index, rva.pde_index, rva.pte_index, pa >> PAGE_SHIFT);
								return STATUS_SUCCESS;
							}
						}

					}
				}
			}

			//printf("System Cache Region found at PML4E index %d [ RVA: %p ]\n", i + 256, rva.AsUINT64);
		}
	}

	//ScanEProcess();

	return STATUS_SUCCESS;
}
