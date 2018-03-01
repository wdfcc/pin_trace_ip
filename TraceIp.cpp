#include "pin.H"
#include<stdio.h>

//定义检查地址
#define CHECKADDRESS (0x41414141)


#define CHECKRET
#define CHECKCALLREG
#define CHECKCALLADDRESS



FILE * outfile;



VOID PIN_FAST_ANALYSIS_CALL CheckRet(VOID * ip,CONTEXT * ctxt)
{
	UINT32 retip = *((UINT32*)PIN_GetContextReg(ctxt, REG_ESP));
	if (retip == CHECKADDRESS)
	{
		fprintf(outfile, "ret:%p\n", ip);
		PIN_ExitApplication(0);
	}
}
VOID PIN_FAST_ANALYSIS_CALL CheckCall(VOID *ip, VOID *callip)
{
	if (*((UINT32*)callip) == CHECKADDRESS)
	{
		fprintf(outfile, "call:%p\n", ip);
		PIN_ExitApplication(0);

	}

}

VOID PIN_FAST_ANALYSIS_CALL CheckCall2(VOID * ip, CONTEXT * ctxt)
{
	UINT16 *Instruction = (UINT16 *)ip;
	ADDRINT EAX = PIN_GetContextReg(ctxt, REG_EAX);
	ADDRINT ECX = PIN_GetContextReg(ctxt, REG_ECX);
	ADDRINT EDX = PIN_GetContextReg(ctxt, REG_EDX);
	ADDRINT EBX = PIN_GetContextReg(ctxt, REG_EBX);
	ADDRINT ESP = PIN_GetContextReg(ctxt, REG_ESP);
	ADDRINT EBP = PIN_GetContextReg(ctxt, REG_EBP);
	ADDRINT ESI = PIN_GetContextReg(ctxt, REG_ESI);
	ADDRINT EDI = PIN_GetContextReg(ctxt, REG_EDI);
	
	switch (*Instruction)
	{
	case 0xD0FF:
		if (EAX == CHECKADDRESS)
		{
			fprintf(outfile, "call:%p\n", ip);
			PIN_ExitApplication(0);
		}
		break;
	case 0xD1FF:
		if (ECX == CHECKADDRESS)
		{
			fprintf(outfile, "call:%p\n", ip);
			PIN_ExitApplication(0);
		}
		break;
	case 0xD2FF:
		if (EDX == CHECKADDRESS)
		{
			fprintf(outfile, "call:%p\n", ip);
			PIN_ExitApplication(0);

		}
		break;
	case 0xD3FF:
		if (EBX == CHECKADDRESS)
		{
			fprintf(outfile, "call:%p\n", ip);
			PIN_ExitApplication(0);

		}
		break;
	case 0xD4FF:
		if (ESP == CHECKADDRESS)
		{
			fprintf(outfile, "call:%p\n", ip);
			PIN_ExitApplication(0);

		}
		break;
	case 0xD5FF:
		if (EBP == CHECKADDRESS)
		{
			fprintf(outfile, "call:%p\n", ip);
			PIN_ExitApplication(0);

		}
		break;
	case 0xD6FF:
		if (ESI == CHECKADDRESS)
		{
			fprintf(outfile, "call:%p\n", ip);
			PIN_ExitApplication(0);

		}
		break;
	case 0xD7FF:
		if (EDI == CHECKADDRESS)
		{
			fprintf(outfile, "call:%p\n", ip);
			PIN_ExitApplication(0);

		}
		break;
	default:
		break;
	}



}
VOID InsCallBack(INS ins, VOID *v)
{
#ifdef CHECKRET
	if (INS_IsRet(ins))
	{

		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CheckRet, IARG_FAST_ANALYSIS_CALL,IARG_INST_PTR,IARG_CONTEXT, IARG_END);

	}
#endif
	if (INS_IsCall(ins))
	{
#ifdef CHECKCALLADDRESS
		if (INS_IsMemoryRead(ins))
		{
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CheckCall, IARG_FAST_ANALYSIS_CALL, IARG_INST_PTR, IARG_MEMORYOP_EA, 0, IARG_END);
		}
#endif
#ifdef CHECKCALLREG
		 if(INS_OperandIsReg(ins, 0))
		{
			
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)CheckCall2, IARG_FAST_ANALYSIS_CALL, IARG_INST_PTR, IARG_CONTEXT, IARG_END);
		}
#endif


	}
}
INT32 Usage()
{
	//初始化失败输出这个工具的功能
	PIN_ERROR("快速查找函数中的溢出点\n"
		+ KNOB_BASE::StringKnobSummary() + "\n");
	return -1;

}
//结束回调函数
VOID Fini(INT32 code, VOID *v)
{
	fclose(outfile);
}

int main(int argc, char *argv[])
{
	if (PIN_Init(argc, argv)) return Usage();
	outfile = fopen("ip.txt","w");

	INS_AddInstrumentFunction(InsCallBack, 0);
	//注册结束回调函数
	PIN_AddFiniFunction(Fini, 0);
	//启动应用程序
	PIN_StartProgram();
	return 0;
}