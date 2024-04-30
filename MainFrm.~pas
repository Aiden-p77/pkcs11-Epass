unit MainFrm;
{=========================================================================

	Copyright(C) Feitian Technologies Co., Ltd.
	All rights reserved.
File:
  MainFrm.pas
Author:
  Allen
CreatedTime:
  20090707
Modified History:
  20090714   solve the exception of exiting.      by Allen
DESC:
	main form.

=========================================================================}
interface

uses
  ShareMem,Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls,CommonFun,pkcs11,Frm_Login,Des3test,Destest,RC2Test,RC4Test,RSATest,
  SCB2Test,SSF33Test;


type
  TFrmMain = class(TForm)
    GroupBox1: TGroupBox;
    ButtDes: TButton;
    ButtDes3: TButton;
    ButtRC2: TButton;
    ButtRC4: TButton;
    ButtRSA: TButton;
    ButtExit: TButton;
    ButtConnectTk: TButton;
    ButtLogin: TButton;
    GroupBox2: TGroupBox;
    Memo: TMemo;
    ButtClearMsg: TButton;
    procedure Button1Click(Sender: TObject);
    procedure FormShow(Sender: TObject);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure ButtConnectTkClick(Sender: TObject);
    procedure ButtLoginClick(Sender: TObject);
    procedure ButtDes3Click(Sender: TObject);
    procedure ButtDesClick(Sender: TObject);
    procedure ButtRC2Click(Sender: TObject);
    procedure ButtRC4Click(Sender: TObject);
    procedure ButtRSAClick(Sender: TObject);
    procedure ButtClearMsgClick(Sender: TObject);
    procedure ButtExitClick(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  FrmMain: TFrmMain;


//------------------------------------------------------------------------
implementation

{$R *.dfm}

procedure TFrmMain.Button1Click(Sender: TObject);
var
  des3Obj:CDES3Test;
begin
  des3Obj:=CDES3Test.Create;
  des3Obj.Test(memo);
  des3Obj.Free;
end;
//------------------------------------------------------------------------
procedure TFrmMain.FormShow(Sender: TObject);
var
  bRet:Boolean;
  sMsg:string;
begin
  //load pkcs11 lib and initialize it
  bRet:=InitializeLib();
  if(not bRet) then begin
    sMsg:='Initialize pkcs#11 library error,library name:'+dllName;
    Memo.Lines.Add(sMsg);
    FinalizeLib();
    exit;
  end;
end;
//------------------------------------------------------------------------

procedure TFrmMain.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  if(g_hSession <> 0) then  begin
    C_CloseSession(g_hSession);
  end;
  FinalizeLib();
  
end;
//------------------------------------------------------------------------
procedure TFrmMain.ButtConnectTkClick(Sender: TObject);
var
  rv:CK_RV;
  ulCount:CK_ULONG;
  SlotList:array of longword;
  pSlotList:CK_SLOT_ID_PTR;
  pUserPin:PChar;
  ulPIN:CK_ULONG;
  ulPrivateKeyAttributeCount:CK_ULONG;
  ulPublicKeyAttributeCount:CK_ULONG;
  sMsg:string;
begin
  ulCount:=0;
  if(g_hSession<>0) then
    exit;
  Screen.Cursor := crHourGlass;
  rv := C_GetSlotList(1, nil, ulCount);
  if(rv<>CKR_OK) then begin
    sMsg:=Format('Can not acquire information of slot, ErrorCode: 0x%.8x',[rv]);
    Memo.Lines.Add(sMsg);
    Screen.Cursor := crDefault;
    exit
  end;
  if(ulCount<=0) then begin
    sMsg:= 'Can not connect to token, make sure one token has been inserted.';
    Memo.Lines.Add(sMsg);
    Screen.Cursor := crDefault;
    exit
  end;
  SetLength(SlotList,ulCount);
  pSlotList:=@SlotList[0];
  rv := C_GetSlotList(1, pSlotList,ulCount);
  if(rv<>CKR_OK) then begin
    sMsg:=Format('Can not acquire information of slot, ErrorCode: 0x%.8x',[rv]);
    Memo.Lines.Add(sMsg);
    Screen.Cursor:=crDefault;
    exit
  end;
  if(ulCount<=0) then begin
    sMsg:= 'Can not connect to token, make sure one token has been inserted.';
    Memo.Lines.Add(sMsg);
    Screen.Cursor := crDefault;
    exit
  end;
  rv := C_OpenSession(SlotList[0],CKF_RW_SESSION or CKF_SERIAL_SESSION,0,0,g_hSession);
  if(rv<>CKR_OK) then begin
    sMsg:=Format('Can not acquire information of slot, ErrorCode: 0x%.8x',[rv]);
    Memo.Lines.Add(sMsg);
    Screen.Cursor:=crDefault;
    exit
  end;
  ButtConnectTk.Enabled:=false;
  ButtLogin.Enabled:=true;
  sMsg:='Connect to token Successfully !';
  Memo.Lines.Add(sMsg);

  Screen.Cursor := crDefault;
end;
//------------------------------------------------------------------------
procedure TFrmMain.ButtLoginClick(Sender: TObject);
var
  sMsg:string;
  pUserPin:PChar;
  rv:longword;
  ulPIN:CK_ULONG;
  pFrm:TFrmLogin;
begin
  pFrm:=TFrmLogin.Create(nil);
  pFrm.EditPin.Clear;
  pFrm.ShowModal;
  if(g_strUserPin='') then begin
    Memo.Lines.Add('You should enter User PIN !');
    pFrm.Free;
    exit
  end;

  ulPIN := Length(g_strUserPin);
  pUserPin:=PChar(g_strUserPin);

  Screen.Cursor := crHourGlass;
  rv:=C_Login(g_hSession,1,pUserPin,ulPIN);
  
  if(rv<>CKR_OK) then begin
    sMsg:=Format('Can not use your User PIN login to token ,ErrorCode: 0x%.8x.',[rv]);
    Memo.Lines.Add(sMsg);
    Screen.Cursor := crDefault;
    pFrm.Free;
    exit
  end;

  sMsg:='Logging in to token Successfully!';
  Memo.Lines.Add(sMsg);
  ButtDes.Enabled:=true;
  ButtDes3.Enabled:=true;
  ButtRC2.Enabled:=true;
  ButtRC4.Enabled:=true;
  ButtRSA.Enabled:=true;
  ButtLogin.Enabled:=false;
  
  pFrm.Free;
  Screen.Cursor := crDefault;
end;
//------------------------------------------------------------------------
procedure TFrmMain.ButtDes3Click(Sender: TObject);
var
  des3Obj:CDes3Test;
begin
  memo.Lines.Add('************************************DES3 TEST**********************************');
  des3Obj:=CDes3Test.Create;
  des3Obj.Test(memo);
  memo.Lines.Add('*******************************************************************************');
  des3Obj.Free;
end;
//--------------------------------------------------------------------------
procedure TFrmMain.ButtDesClick(Sender: TObject);
var
  desObj:CDesTest;
begin
  memo.Lines.Add('************************************DES TEST**********************************');
  desObj:=CDesTest.Create();
  desObj.Test(memo);
  memo.Lines.Add('******************************************************************************');
  desObj.Free;
end;
//---------------------------------------------------------------------------
procedure TFrmMain.ButtRC2Click(Sender: TObject);
var
  rc2Obj:CRC2Test;
begin
  memo.Lines.Add('************************************RC2 TEST**********************************');
  rc2Obj:=CRC2Test.Create;
  rc2Obj.Test(memo);
  memo.Lines.Add('******************************************************************************');
  rc2Obj.Free;
end;
//--------------------------------------------------------------------------

procedure TFrmMain.ButtRC4Click(Sender: TObject);
var
  rc4Obj:CRC4Test;
begin
  memo.Lines.Add('************************************RC4 TEST**********************************');
  rc4Obj:=CRC4Test.Create;
  rc4Obj.Test(memo);
  memo.Lines.Add('******************************************************************************');
  rc4Obj.Free;
end;
//------------------------------------------------------------------------
procedure TFrmMain.ButtRSAClick(Sender: TObject);
var
  rsaObj:CRsaTest;
begin
  
  memo.Lines.Add('************************************RSA TEST**********************************');
  rsaObj:=CRsaTest.Create;
  rsaObj.RSATest(memo);
  memo.Lines.Add('******************************************************************************');
  rsaObj.Free;
end;


//------------------------------------------------------------------------
procedure TFrmMain.ButtClearMsgClick(Sender: TObject);
begin
  memo.Clear;
end;
//------------------------------------------------------------------------
procedure TFrmMain.ButtExitClick(Sender: TObject);
begin
  Close;
end;
//------------------------------------------------------------------------
end.
