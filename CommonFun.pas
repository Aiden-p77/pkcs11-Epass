unit CommonFun;
{=========================================================================

Copyright(C) Feitian Technologies Co., Ltd.
All rights reserved.

FILE:
	BaseAll.pas
Author:
  Allen
Created Time:
  20090706

DESC:
	base class:Find the token and open/close session.
=========================================================================}

interface

uses
  ShareMem,windows,sysutils,pkcs11,StdCtrls,dialogs;
const
  dllname:string= 'ShuttleCsp11_3003.dll';

//-----------------------------------------------------------------------
var
  g_hDll:HMODULE;
  g_hSession:CK_SESSION_HANDLE;
  g_bIsIni:Boolean;
  function FinalizeLib():CK_RV;
  function InitializeLib():Boolean;
  procedure ShowData(pData:array of byte;ulDataLen:longword;memo:TMemo);

//----------------------------------------------------------------------
implementation
function InitializeLib():Boolean;
var
  rv:longword;
begin
  g_bIsIni:=false;
  g_hDll:=LoadLibrary(Pchar(dllname));
  if(g_hDll=0) then begin
    MessageDlg('Failed to load the pkcs11 library!',mtError,[mbOk],0);
    result:= false;
    exit
    end
  else
  begin
    @C_Initialize:=GetProcAddress(g_hDll, PChar('C_Initialize'));
    @C_Finalize:=GetProcAddress(g_hDll, PChar('C_Finalize'));
    @C_GetSlotList:=GetProcAddress(g_hDll, PChar('C_GetSlotList'));
    @C_GetSlotInfo:=GetProcAddress(g_hDll, PChar('C_GetSlotInfo'));
    @C_GetInfo:=GetProcAddress(g_hDll,PChar('C_GetInfo'));
    @C_GetTokenInfo:=GetProcAddress(g_hDll,PChar('C_GetTokenInfo'));
    @C_OpenSession:=GetProcAddress(g_hDll,PChar('C_OpenSession'));
    @C_CloseSession:=GetProcAddress(g_hDll,PChar('C_CloseSession'));
    @C_Login:=GetProcAddress(g_hDll,PChar('C_Login'));
    @C_GenerateKey:=GetProcAddress(g_hDll,PChar('C_GenerateKey'));
    @C_GenerateKeyPair:=GetProcAddress(g_hDll,PChar('C_GenerateKeyPair'));
    @C_DestroyObject:=GetProcAddress(g_hDll,PChar('C_DestroyObject'));
    @C_EncryptInit:=GetProcAddress(g_hDll,PChar('C_EncryptInit'));
    @C_DecryptInit:=GetProcAddress(g_hDll,PChar('C_DecryptInit'));
    @C_Encrypt:=GetProcAddress(g_hDll,PChar('C_Encrypt'));
    @C_Decrypt:=GetProcAddress(g_hDll,PChar('C_Decrypt'));
    @C_EncryptUpdate:=GetProcAddress(g_hDll,PChar('C_EncryptUpdate'));
    @C_DecryptUpdate:=GetProcAddress(g_hDll,PChar('C_DecryptUpdate'));
    @C_EncryptFinal:=GetProcAddress(g_hDll,PChar('C_EncryptFinal'));
    @C_DecryptFinal:=GetProcAddress(g_hDll,PChar('C_DecryptFinal'));
    @C_Sign:=GetProcAddress(g_hDll,PChar('C_Sign'));
    @C_SignInit:=GetProcAddress(g_hDll,PChar('C_SignInit'));
    @C_VerifyInit:=GetProcAddress(g_hDll,PChar('C_VerifyInit'));
    @C_Verify:=GetProcAddress(g_hDll,PChar('C_Verify'));
    if(@C_Initialize=nil)then begin
      MessageDlg('Get C_Initialize function failed!',mtError,[mbOk],0);
      result:=false;
      exit
    end
    else if(@C_Finalize=nil) then begin
      MessageDlg('Get C_Finalize function failed!',mtError,[mbOk],0);
      result:=false;
      exit
    end
    else if(@C_GetSlotList=nil) then begin
      MessageDlg('Get C_GetSlotList function failed!',mtError,[mbOk],0);
      result:=false;
      exit
    end
    else if(@C_GetSlotInfo=nil) then begin
      MessageDlg('Get C_GetSlotInfo function failed!',mtError,[mbOk],0);
      result:=false;
      exit
    end
    else if(@C_GetInfo=nil) then begin
      MessageDlg('Get C_GetInfo function failed!',mtError,[mbOk],0);
      result:=false;
      exit
    end
    else if(@C_GetTokenInfo=nil) then begin
      MessageDlg('Get C_GetTokenInfo function failed!',mtError,[mbOk],0);
      result:=false;
      exit
    end
    else if(@C_OpenSession=nil) then begin
      MessageDlg('Get C_OpenSession function failed!',mtError,[mbOk],0);
      result:=false;
      exit
    end
    else if(@C_CloseSession=nil) then begin
      MessageDlg('Get C_CloseSession function failed!',mtError,[mbOk],0);
      result:=false;
      exit
    end
    else if(@C_Login=nil) then begin
      MessageDlg('Get C_Login function failed!',mtError,[mbOk],0);
      result:=false;
      exit
    end
    else if(@C_GenerateKey=nil) then begin
      MessageDlg('Get C_GenerateKey function failed!',mtError,[mbOk],0);
      result:=false;
      exit
    end
    else if(@C_EncryptInit=nil) then begin
      MessageDlg('Get C_EncryptInit function failed!',mtError,[mbOk],0);
      result:=false;
      exit
    end
    else if(@C_DecryptInit=nil) then begin
      MessageDlg('Get C_DecryptInit function failed!',mtError,[mbOk],0);
      result:=false;
      exit
    end
    else if(@C_Encrypt=nil) then begin
      MessageDlg('Get C_Encrypt function failed!',mtError,[mbOk],0);
      result:=false;
      exit
    end
    else if(@C_Decrypt=nil) then begin
      MessageDlg('Get C_Decrypt function failed!',mtError,[mbOk],0);
      result:=false;
      exit
    end
    else if(@C_EncryptUpdate=nil) then begin
      MessageDlg('Get C_EncryptUpdate function failed!',mtError,[mbOk],0);
      result:=false;
      exit
    end
    else if(@C_DecryptUpdate=nil) then begin
      MessageDlg('Get C_DecryptUpdate function failed!',mtError,[mbOk],0);
      result:=false;
      exit
    end
    else if(@C_EncryptFinal=nil) then begin
      MessageDlg('Get C_EncryptFinal function failed!',mtError,[mbOk],0);
      result:=false;
      exit
    end
    else if(@C_DecryptFinal=nil) then begin
      MessageDlg('Get C_DecryptFinal function failed!',mtError,[mbOk],0);
      result:=false;
      exit;
    end;
    rv:=C_Initialize(0);
    if(rv <> CKR_OK) then begin
      MessageDlg('Call C_Initialize function failed!',mtError,[mbOk],0);
      result:=false;
      exit;
    end;
    g_bIsIni:=true;
    result:=true;
    exit;
  end;
end;
//-----------------------------------------------------------------------
function FinalizeLib():CK_RV;

begin
  if(g_bIsIni) then begin
    C_Finalize(0);
  end;

	Sleep(500);
	if(g_hDll <> 0) then begin
	  FreeLibrary(g_hDll);
		g_hDll := 0;
	end;
  result:=CKR_OK;
  exit;
end;
//----------------------------------------------------------------------
procedure ShowData(pData:array of byte;ulDataLen:longword;memo:TMemo);
var
  sMsg:string;
  i:integer;
begin

  for i:=0 to ulDataLen-1 do begin
    if((i mod 16)=0) then begin
      sMsg:=sMsg+#13#10;
    end;
    sMsg:=sMsg+Format('%.3x',[pData[i]]);
    sMsg:=sMsg+' ';

  end;

  memo.Lines.Add(Format('Length of data to be showed is:%d',[ulDataLen]));
  //memo.Lines.Add('-----------------------------------------------------------------------------------------------');
  memo.Lines.Add(sMsg);
  memo.Lines.Add('');
  //memo.Lines.Add('-----------------------------------------------------------------------------------------------');
end;
//----------------------------------------------------------------------
end.
