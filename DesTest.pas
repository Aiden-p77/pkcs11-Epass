unit DesTest;
{=========================================================================

	Copyright(C) Feitian Technologies Co., Ltd.
	All rights reserved.
File:
  DesTest.pas
Author:
  Allen
CreatedTime:
  20090707
DESC:
	implementation of the DesTest class.

=========================================================================}
interface
uses
   ShareMem,Windows, SysUtils,pkcs11,CommonFun,StdCtrls;
type
  CDesTest=class
  public
    function Test(memo:TMemo):integer;
  private
    m_hKey:CK_ULONG;
  	function GenerateKey(memo:TMemo):integer;
	  function crypt_Single(memo:TMemo):integer;
	  function crypt_Update(memo:TMemo):integer;
end;

//-------------------------------------------------------------------------
implementation
function CDesTest.GenerateKey(memo:TMemo):integer;
var
  rv:longword;
  oClass:CK_OBJECT_CLASS;
  keyType:CK_KEY_TYPE;
  bTrue:CK_BBOOL;
  bFalse:CK_BBOOL;
  ulLen:CK_ULONG;
  ulCount:CK_ULONG;
  mechanism : CK_MECHANISM;
  DesTem:array[0..6] of CK_ATTRIBUTE;
  sMsg:string;
begin
  oClass := CKO_SECRET_KEY;
  keyType:=CKK_DES;
  bTrue:=1;
  bFalse:=0;
  ulLen:=8;
  ulCount:=7;
  mechanism.mechanism:=CKM_DES_KEY_GEN;
  mechanism.pParameter:=nil;
  mechanism.ulParameterLen:=0;

  DesTem[0].attrtype:=CKA_CLASS;
  DesTem[0].pValue:=@oClass;
  DesTem[0].ulValueLen:=sizeof(CK_OBJECT_CLASS);

  DesTem[1].attrtype:=CKA_KEY_TYPE;
  DesTem[1].pValue:=@keyType;
  DesTem[1].ulValueLen:=sizeof(CK_KEY_TYPE);

  DesTem[2].attrtype:=CKA_TOKEN;
  DesTem[2].pValue:=@bFalse;
  DesTem[2].ulValueLen:=sizeof(CK_BBOOL);

  DesTem[3].attrtype:=CKA_PRIVATE;
  DesTem[3].pValue:=@bTrue;
  DesTem[3].ulValueLen:=sizeof(CK_BBOOL);

  DesTem[4].attrtype:=CKA_ENCRYPT;
  DesTem[4].pValue:=@bTrue;
  DesTem[4].ulValueLen:=sizeof(CK_BBOOL);

  DesTem[5].attrtype:=CKA_DECRYPT;
  DesTem[5].pValue:=@bTrue;
  DesTem[5].ulValueLen:=sizeof(CK_BBOOL);

  DesTem[6].attrtype:=CKA_VALUE_LEN;
  DesTem[6].pValue:=@ulLen;
  DesTem[6].ulValueLen:=sizeof(CK_ULONG);
  memo.Lines.Add('');
  memo.Lines.Add('Generate key...');
  rv :=C_GenerateKey(g_hSession, @mechanism, @Destem, ulCount, @m_hKey);
  if(rv <> CKR_OK) then begin
    sMsg:=Format('Call C_GenerateKey error, error code:0x%.8x',[rv]);
    memo.Lines.Add(sMsg);
    result:=-1;
    exit;
  end;
  sMsg:=('Call C_GenerateKey successfully');
  memo.Lines.Add(sMsg);
  result:=0;
  exit;

end;

//-------------------------------------------------------------------------
function CDesTest.crypt_Single(memo:TMemo):integer;
var
  rv:longword;
  i,i0:integer;
  ulIn,ulOut,ulTemp:CK_ULONG;
  bIn:array[0..1023] of CK_BYTE;
  bTemp:array[0..1023] of CK_BYTE;
  bOut:array[0..1023] of CK_BYTE;
  Mechanism:array[0..2] of CK_ULONG;
  bHint:array[0..2] of string;
  ckMechanism:CK_MECHANISM;
  sMsg:string;
const
  iv:array[0..7] of CK_BYTE=(CK_BYTE('*'),CK_BYTE('2'),CK_BYTE('1'),CK_BYTE('0'),CK_BYTE('4'),CK_BYTE('z'),CK_BYTE('y'),CK_BYTE('b'));

begin

  ZeroMemory(@bIn,1024);
  ZeroMemory(@bTemp,1024);
  ZeroMemory(@bOut,1024);
  ulOut := 0;
  ulTemp := 0;

  Mechanism[0]:=CKM_DES_CBC;
  Mechanism[1]:=CKM_DES_ECB;
  Mechanism[2]:=CKM_DES_CBC_PAD;
  bHint[0]:='CKM_DES_CBC:';
  bHint[1]:='CKM_DES_ECB:';
  bHint[2]:='CKM_DES_CBC_PAD:';
  memo.Lines.Add('');
  memo.Lines.Add('DES: C_Encrypt/C_Decrypt: ');
	for i:=0 to 2 do begin
		ulIn := 256;
		if(i=2) then
			ulIn := 337;
		for i0:= 0 to ulIn-1 do begin
			bIn[i0] := CK_BYTE(i0);
    end;

    Memo.Lines.Add(bHint[i]);

    //initialize encryption:
    ZeroMemory(@ckMechanism,sizeof(CK_MECHANISM));
    ckMechanism.mechanism:=Mechanism[i];
    ckMechanism.pParameter:=@iv;
    ckMechanism.ulParameterLen:=8;

		Memo.Lines.Add('Encrypting initialize...');
		rv :=  C_EncryptInit(g_hSession, @ckMechanism, m_hKey);
    if(rv <> CKR_OK) then begin
      sMsg:=Format('Call C_EncryptInit error,error code:0x%.8x',[rv]);
      Memo.Lines.Add(sMsg);
      result:=-1;
      exit;
    end;

		Memo.Lines.Add('Encrypt the message...');
		//Get the encrypted buffer's size:
		//If you do not declare the result's buffer previous,
		//you should invoke twice to get the buffer's size, such as:[Decrypt is similar]
		rv :=  C_Encrypt(g_hSession, @bIn, ulIn, nil, @ulTemp);
    if(rv <> CKR_OK) then begin
      sMsg:=Format('Call C_Encrypt to get buffer size error,error code:%.8x',[rv]);
      Memo.Lines.Add(sMsg);
      result:=-2;
      exit;
    end;
		//encrypt data:
		rv := C_Encrypt(g_hSession, @bIn, ulIn, @bTemp, @ulTemp);
    if(rv <> CKR_OK) then begin
      sMsg:=Format('Call C_Encrypt to encrypt message error,error code:0x%.8x',[rv]);
      Memo.Lines.Add(sMsg);
      result:=-3;
      exit;
    end;

		memo.Lines.Add('Data encrypted: ');
		ShowData(bTemp, ulTemp,memo);

    //initialize decryption
		memo.Lines.Add('Decrypting initialize...');
		rv :=C_DecryptInit(g_hSession, @ckMechanism, m_hKey);
		if(rv <> CKR_OK) then begin
      sMsg:=Format('Call C_DecryptInit error,error code:0x%.8x',[rv]);
      Memo.Lines.Add(sMsg);
      result:=-4;
      exit;
    end;
    memo.Lines.Add('Decrypt the message...');
		//Get buffer's size:
		rv :=C_Decrypt(g_hSession, @bTemp, ulTemp, nil, @ulOut);
    if(rv <> CKR_OK) then begin
      sMsg:=Format('Call C_Decrypt to get buffer size error,error code:0x%.8x',[rv]);
      Memo.Lines.Add(sMsg);
      result:=-5;
      exit;
    end;
		//Get decrypted data:
		rv := C_Decrypt(g_hSession, @bTemp, ulTemp, @bOut, @ulOut);
    if(rv <> CKR_OK) then begin
      sMsg:=Format('Call C_Decrypt to get decrypt message error,error code:0x%.8x',[rv]);
      Memo.Lines.Add(sMsg);
      result:=-6;
      exit;
    end;

		memo.Lines.Add('Data decrypted: ');
		ShowData(bOut, ulOut,memo);

	 //compare the original message and decrypted message
		if(false =CompareMem(@bIn,@bOut,ulOut)) then begin
      Memo.Lines.Add('Decrypted data is not as same as the original!');
      result:=-7;
      exit;
    end
    else begin
      Memo.Lines.Add('Decrypted data is as same as the original!');
    end;
    memo.Lines.Add('');
	end;

  result:=0;
  exit;
end;
//-------------------------------------------------------------------------
function CDesTest.crypt_Update(memo:TMemo):integer;
var
  rv:CK_RV;
  bTemp:array[0..1024*3-1] of CK_BYTE;
  bIn:array[0..1024*3-1] of CK_BYTE;
  bOut:array[0..1024*3-1] of CK_BYTE;
  ulIn,ulOut,ulTemp,ulEncrypted,ulDecrypt:CK_ULONG;
  bHint:array[0..2] of string;
  ckMechanism:CK_MECHANISM;
  i,i0:longword;
  sMsg:string;
const
  Mechanism:array[0..2] of CK_ULONG=(CKM_DES_CBC,CKM_DES_ECB,CKM_DES_CBC_PAD);
  iv:array[0..7] of CK_BYTE=(CK_BYTE('*'),CK_BYTE('2'),CK_BYTE('1'),CK_BYTE('0'),CK_BYTE('4'),CK_BYTE('z'),CK_BYTE('y'),CK_BYTE('b'));
  ulEnc1stPice= 33;
  ulDec1stPice= 11;
begin
  ZeroMemory(@bIn,1024*3);
  ZeroMemory(@bOut,1024*3);
  ZeroMemory(@bTemp,1024*3);
//  ulIn:=0;
  ulOut:=0;
  ulTemp:=0;
	bHint[0] := 'CKM_DES_CBC: ';
  bHint[1] := 'CKM_DES_ECB: ';
  bHint[2] := 'CKM_DES_CBC_PAD: ';

	memo.Lines.Add('');
  memo.Lines.Add('DES: C_EncryptUpdate/C_DecryptUpdate: ');
	for i:=0 to 2 do begin
		ulIn := 1000;
    //CKM_RC2_CBC_PAD
		if i = 2 then begin
			ulIn := 1000;
    end;
		for i0 := 0 to ulIn-1 do begin
			bIn[i0] := CK_BYTE(i0);
    end;

		memo.Lines.Add(bHint[i]);
		//ecnrypt init:
    ckMechanism.mechanism:=Mechanism[i];
    ckMechanism.pParameter:=@iv;
    ckMechanism.ulParameterLen:=8;
		memo.Lines.Add('Encrypting initialize...');
    rv :=C_EncryptInit(g_hSession,@ckMechanism, m_hKey);
    if(rv <> CKR_OK) then begin
      sMsg:=Format('Call C_EncryptInit error,error code:0x%.8x',[rv]);
      Memo.Lines.Add(sMsg);
      result:=-1;
      exit;
    end;

		ulEncrypted := 0;
		memo.Lines.Add('Encrypt the message...');
		//invoked twice:
    //first time,get buffer's size.
		rv :=C_EncryptUpdate(g_hSession, @bIn, ulEnc1stPice, nil, @ulTemp);
    if(rv <> CKR_OK) then begin
      sMsg:=Format('Call C_EncryptUpdate to get buffer size error,error code:0x%.8x',[rv]);
      Memo.Lines.Add(sMsg);
      result:=-2;
      exit;
    end;
    //second time,encrypt
		rv :=C_EncryptUpdate(g_hSession, @bIn, ulEnc1stPice, @bTemp, @ulTemp);
    if(rv <> CKR_OK) then begin
      sMsg:=Format('Call C_EncryptUpdate to encrypt message error,errCode:0x%.8x',[rv]);
      Memo.Lines.Add(sMsg);
      result:=-3;
      exit;
    end;
		ulEncrypted:=ulEncrypted+ulTemp;
		ulTemp := 0;

		//encrypt:
		//invoked twice:
		rv := C_EncryptUpdate(g_hSession,  @bIn[ulEnc1stPice], ulIn-ulEnc1stPice, nil, @ulTemp);//get buffer's size.
    if(rv <> CKR_OK) then begin
      sMsg:=Format('Call C_EncryptUpdate to get buffer size error,error code:0x%.8x',[rv]);
      Memo.Lines.Add(sMsg);
      result:=-4;
      exit;
    end;
		rv := C_EncryptUpdate(g_hSession, @bIn[ulEnc1stPice], ulIn-ulEnc1stPice, @bTemp[ulEncrypted], @ulTemp);
    if(rv <> CKR_OK) then begin
      sMsg:=Format('Call C_EncryptUpdate to encrypt message error,error code:0x%.8x',[rv]);
      Memo.Lines.Add(sMsg);
      result:=-5;
      exit;
    end;

		ulEncrypted:=ulEncrypted+ulTemp;
		ulTemp := 0;
		rv := C_EncryptFinal(g_hSession, @bTemp[ulEncrypted], @ulTemp);
    if(rv <> CKR_OK) then begin
      sMsg:=Format('Call C_EncryptFinal to encrypt message error,error code:0x%.8x',[rv]);
      Memo.Lines.Add(sMsg);
      result:=-6;
      exit;
    end;
		ulEncrypted:=ulEncrypted+ulTemp;
		ulTemp := 0;
		memo.Lines.Add('Data encrypted: ');
		ShowData(bTemp, ulEncrypted,memo);

		memo.Lines.Add('Decrypting initialize...');
		rv := C_DecryptInit(g_hSession, @ckMechanism, m_hKey);
		if(rv <> CKR_OK) then begin
      sMsg:=Format('Call C_DecryptInit error,error code:0x%.8x',[rv]);
      Memo.Lines.Add(sMsg);
      result:=-7;
      exit;
    end;
		//Get buffer's size:
		ulDecrypt := 0;
		rv := C_DecryptUpdate(g_hSession, @bTemp, ulDec1stPice, nil, @ulOut);
    if(rv <> CKR_OK) then begin
      sMsg:=Format('Call C_DecryptUpdate to get buffer size error,error code:0x%.8x',[rv]);
      Memo.Lines.Add(sMsg);
      result:=-8;
      exit;
    end;
		rv := C_DecryptUpdate(g_hSession, @bTemp, ulDec1stPice, @bOut,@ulOut);
    if(rv <> CKR_OK) then begin
      sMsg:=Format('Call C_DecryptUpdate to decrypt message error,error code:0x%.8x',[rv]);
      Memo.Lines.Add(sMsg);
      result:=-9;
      exit;
    end;
		ulDecrypt:=ulDecrypt+ulOut;
		ulOut := 0;
		//Get decrypted data:
		rv :=C_DecryptUpdate(g_hSession, @bTemp[ulDec1stPice], ulEncrypted-ulDec1stPice, nil, @ulOut);
    if(rv <> CKR_OK) then begin
      sMsg:=Format('Call C_DecryptUpdate to get buffer size error,error code:0x%.8x',[rv]);
      Memo.Lines.Add(sMsg);
      result:=-10;
      exit;
    end;
		rv :=C_DecryptUpdate(g_hSession, @bTemp[ulDec1stPice], ulEncrypted-ulDec1stPice, @bOut[ulDecrypt], @ulOut);
    if(rv <> CKR_OK) then begin
      sMsg:=Format('Call C_DecryptUpdate to decrypt message error,error code:0x%.8x',[rv]);
      Memo.Lines.Add(sMsg);
      result:=-11;
      exit;
    end;
		ulDecrypt:=ulDecrypt+ulOut;
		ulOut := 0;

		rv := C_DecryptFinal(g_hSession, @bOut[ulDecrypt], @ulOut);
    if(rv <> CKR_OK) then begin
      sMsg:=Format('Call C_DecryptFinal error,error code:0x%.8x',[rv]);
      Memo.Lines.Add(sMsg);
      result:=-12;
      exit;
    end;
		ulDecrypt :=ulDecrypt+ulOut;

		memo.Lines.Add('Data decrypted: ');
		ShowData(bOut, ulDecrypt,memo);

		if(false = CompareMem(@bIn,@bOut, ulDecrypt)) then begin
      Memo.Lines.Add('Decrypted data is not as same as the original!');
      result:=-13;
      exit;
    end
    else begin
      Memo.Lines.Add('Decrypted data is as same as the original!');
    end;
    memo.Lines.Add('');
	end;
  result:=0;
  exit;
end;

//-----------------------------------------------------------------------
function CDesTest.Test(memo:TMemo):integer;
var
  rv:integer;
begin
	GenerateKey(memo);
  if(m_hKey=0) then begin
    result:=-1;
    exit;
  end;
	rv:=crypt_Single(memo);
  if(rv <> 0) then begin
    result:=-2;
    exit;
  end;
 	rv:=crypt_Update(memo);
  if(rv <> 0) then begin
    result:=-3;
    exit;
  end;
  result:=0;
  exit;
end;
//-------------------------------------------------------------------------
end.
