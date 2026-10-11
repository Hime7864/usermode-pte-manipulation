#include <intrinsics.hpp>

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

	auto PteAddress = (LINEAR_ADDRESS)PfnDatabase[page >> PAGE_SHIFT].PteAddress;
	if (PteAddress.pml4e_index < 256)
	{
		return false;// usermode pte will miss identify page as normal
	}

	auto type = MiGetSystemRegionType(PteAddress.AsPointer);
	if (type != AssignedRegionSystemCache)
	{
		return false;// pfn page is not marked as system cache
	}

	return true;
}


static void ReportUsermodeLeaf(PEPROCESS eproc, LINEAR_ADDRESS rva, UINT64 pfn)
{
	auto type = MiGetSystemRegionType(MmGetVirtualForPhysical(pfn << PAGE_SHIFT));

	if (!type)
	{
		return;
	}

	if (type == AssignedRegionSystemPtes)
	{
		printf("Sessioned PID 0x%08X [ RVA: %p | PFN: %010LLX ] -> type: %s (you should never see this)\n",
			PsGetProcessId(eproc), rva.AsUINT64, pfn, GetRegionName(type));
		return;
	}

	printf("Sessioned PID 0x%08X [ RVA: %p | PFN: %010LLX ] -> type: %s (normal)\n",
		PsGetProcessId(eproc), rva.AsUINT64, pfn, GetRegionName(type));
}


void ValidateUsermodePageMapping(PEPROCESS eproc)
{
	KAPC_STATE apc;

	auto dtb = *(UINT64*)((UINT64)eproc + 0x28) & ~0xFFF;

	KeStackAttachProcess(eproc, &apc);

	auto pml4_pa = dtb;
	if (!ValidateTranslation(pml4_pa))
	{
		printf("[PID 0x%08X] PfnDatabase validation failed! PML4\n", PsGetProcessId(eproc));
		KeUnstackDetachProcess(&apc);
		return;
	}

	auto pml4 = (MMPTE_HARDWARE*)MmGetVirtualForPhysical(pml4_pa);
	for (int l1 = 0; l1 < 256; l1++)
	{
		if (pml4[l1].Valid)
		{
			auto pdpt_pa = pml4[l1].PageFrameNumber << PAGE_SHIFT;
			if (!ValidateTranslation(pdpt_pa))
			{
				printf("[PID 0x%08X] PfnDatabase validation failed! PDPT\n", PsGetProcessId(eproc));
				KeUnstackDetachProcess(&apc);
				return;
			}

			auto pdpt = (MMPTE_HARDWARE*)MmGetVirtualForPhysical(pdpt_pa);
			for (int l2 = 0; l2 < 512; l2++)
			{
				if (pdpt[l2].Valid)
				{
					if (pdpt[l2].LargePage)
					{
						LINEAR_ADDRESS rva;
						rva.pml4e_index = l1;
						rva.pdpte_index = l2;
						ReportUsermodeLeaf(eproc, rva, pdpt[l2].PageFrameNumber);
						continue;
					}

					auto pdt_pa = pdpt[l2].PageFrameNumber << PAGE_SHIFT;
					if (!ValidateTranslation(pdt_pa))
					{
						printf("[PID 0x%08X] PfnDatabase validation failed! PDT\n", PsGetProcessId(eproc));
						KeUnstackDetachProcess(&apc);
						return;
					}

					auto pdt = (MMPTE_HARDWARE*)MmGetVirtualForPhysical(pdt_pa);
					for (int l3 = 0; l3 < 512; l3++)
					{
						if (pdt[l3].Valid)
						{
							if (pdt[l3].LargePage)
							{
								LINEAR_ADDRESS rva;
								rva.pml4e_index = l1;
								rva.pdpte_index = l2;
								rva.pde_index = l3;
								ReportUsermodeLeaf(eproc, rva, pdt[l3].PageFrameNumber);
								continue;
							}

							auto pte_pa = pdt[l3].PageFrameNumber << PAGE_SHIFT;
							if (!ValidateTranslation(pte_pa))
							{
								printf("[PID 0x%08X] PfnDatabase validation failed! PTE\n", PsGetProcessId(eproc));
								KeUnstackDetachProcess(&apc);
								return;
							}

							auto pte = (MMPTE_HARDWARE*)MmGetVirtualForPhysical(pte_pa);
							for (int l4 = 0; l4 < 512; l4++)
							{
								if (pte[l4].Valid)
								{
									LINEAR_ADDRESS rva;
									rva.pml4e_index = l1;
									rva.pdpte_index = l2;
									rva.pde_index = l3;
									rva.pte_index = l4;
									ReportUsermodeLeaf(eproc, rva, pte[l4].PageFrameNumber);
								}
							}
						}
					}
				}
			}
		}
	}
	KeUnstackDetachProcess(&apc);
	return;
}

void ScanEProcess()
{
	auto flink = (UINT64)PsInitialSystemProcess();
	auto o_UniqueProcessId = *(UINT32*)((UINT64)nt.fn_PsGetProcessId + 0x3);// fix for 22H2 & 24H2
	do
	{
		if (PsGetProcessId((PEPROCESS)flink) != 4)
		{
			auto PEB = *(UINT64*)(flink + o_UniqueProcessId + 0x110);
			if (PEB)
			{
				ValidateUsermodePageMapping((PEPROCESS)flink);
			}
		}
		flink = *(UINT64*)((UINT64)flink + o_UniqueProcessId + 0x8) - (o_UniqueProcessId + 0x8);
	} while (flink != (UINT64)PsInitialSystemProcess());
	printf("Usermode pte scan completed\n");
	return;
}


NTSTATUS DriverEntry()
{
	ScanEProcess();

	return STATUS_SUCCESS;
}
