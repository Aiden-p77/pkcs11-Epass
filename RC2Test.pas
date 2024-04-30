unit RC2Test;
{=========================================================================

	Copyright(C) Feitian Technologies Co., Ltd.
	All rights reserved.

FILE:
	rc2test.pas

DESC:
	implementation of the RC2Test class.
=========================================================================}
interface
uses
   ShareMem,Windows, SysUtils,pkcs11,CommonFun,StdCtrls;
type
  CRC2Test=class
  public
    function Test(memo:TMemo):integer;
  private
    m_hKey:CK_ULONG;
  	function GenerateKey(memo:TMemo):integer;
	  function crypt_Single(memo:TMemo):integer;
	  function crypt_Update(memo:TMemo):integer;
end;

//-----------------------------------------------------------------------
implementation
function CRC2Test.GenerateKey(memo:TMemo):integer;
var
  rv:longword;
  oClass:CK_OBJECT_CLASS;
  keyType:CK_KEY_TYPE;
  bTrue:CK_BBOOL;
  bFalse:CK_BBOOL;
  ulLen:CK_ULONG;
  ulCount:CK_ULONG;
  mechanism : CK_MECHANISM;
  rc2Tem:array[0..6] of CK_ATTRIBUTE;
  sMsg:string;
begin
  oClass := CKO_SECRET_KEY;
  keyType:=CKK_RC2;
  bTrue:=1;
  bFalse:=0;
  ulLen:=16;
  ulCount:=7;
  mechanism.mechanism:=CKM_RC2_KEY_GEN;
  mechanism.pParameter:=nil;
  mechanism.ulParameterLen:=0;

  rc2Tem[0].attrtype:=CKA_CLASS;
  rc2Tem[0].pValue:=@oClass;
  rc2Tem[0].ulValueLen:=sizeof(CK_OBJECT_CLASS);

  rc2Tem[1].attrtype:=CKA_KEY_TYPE;
  rc2Tem[1].pValue:=@keyType;
  rc2Tem[1].ulValueLen:=sizeof(CK_KEY_TYPE);
  
  rc2Tem[2].attrtype:=CKA_TOKEN;
  rc2Tem[2].pValue:=@bFalse;
  rc2Tem[2].ulValueLen:=sizeof(CK_BBOOL);

  rc2Tem[3].attrtype:=CKA_PRIVATE;
  rc2Tem[3].pValue:=@bTrue;
  rc2Tem[3].ulValueLen:=sizeof(CK_BBOOL);
  
  rc2Tem[4].attrtype:=CKA_ENCRYPT;
  rc2Tem[4].pValue:=@bTrue;
  rc2Tem[4].ulValueLen:=sizeof(CK_BBOOL);

  rc2Tem[5].attrtype:=CKA_DECRYPT;
  rc2Tem[5].pValue:=@bTrue;
  rc2Tem[5].ulValueLen:=sizeof(CK_BBOOL);

  rc2Tem[6].attrtype:=CKA_VALUE_LEN;
  rc2Tem[6].pValue:=@ulLen;
  rc2Tem[6].ulValueLen:=sizeof(CK_ULONG);
  memo.Lines.Add('');
  memo.Lines.Add('Generate key...');
  rv :=C_GenerateKey(g_hSession, @mechanism, @rc2tem, ulCount, @m_hKey);
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
//-----------------------------------------------------------------------
function CRC2Test.crypt_Single(memo:TMemo):integer;
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
  Param:CK_RC2_CBC_PARAMS;
const
  iv:array[0..7] of CK_BYTE=(CK_BYTE('*'),CK_BYTE('2'),CK_BYTE('1'),CK_BYTE('0'),CK_BYTE('4'),CK_BYTE('z'),CK_BYTE('y'),CK_BYTE('b'));

begin

  ZeroMemory(@bIn,1024);
  ZeroMemory(@bTemp,1024);
  ZeroMemory(@bOut,1024);
//	ulIn := 0;
  ulOut := 0;
  ulTemp := 0;

  Mechanism[0]:=CKM_RC2_CBC;
  Mechanism[1]:=CKM_RC2_ECB;
  Mechanism[2]:=CKM_RC2_CBC_PAD;
  bHint[0]:='CKM_RC2_CBC:';
  bHint[1]:='CKM_RC2_ECB:';
  bHint[2]:='CKM_RC2_CBC_PAD:';

  memo.Lines.Add('');
  memo.Lines.Add('RC2: C_Encrypt/C_Decrypt: ');
	for i:=0 to 2 do begin
		ulIn := 256;
		if(i=2) then
			ulIn := 337;
		for i0:= 0 to ulIn-1 do begin
			bIn[i0] := CK_BYTE(i0);
    end;

    Memo.Lines.Add(bHint[i]);
    CopyMemory(@Param.iv,@iv, 8);
		Param.ulEffectiveBits := 16*8;
    //initialize encryption:
    ZeroMemory(@ckMechanism,sizeof(CK_MECHANISM));
    ckMechanism.mechanism:=Mechanism[i];
    ckMechanism.pParameter:=@Param;
    ckMechanism.ulParameterLen:=sizeof(CK_RC2_CBC_PARAMS);

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
      sMsg:=Format('Call C_Encrypt to get buffer size error,error code:0x%.8x',[rv]);
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
    memo.Lines.Add('Decrypt the message.');
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
      Memo.Lines.Add('Decrypted data is as same as the original!');
      result:=-7;
      exit;
    end
    else begin
       Memo.Lines.Add('Decrypted data is as same as the original!');
    end;
    memo.Lines.add('');
	end;
  result:=0;
  exit;
end;

//-----------------------------------------------------------------------
function CRC2Test.crypt_Update(memo:TMemo):integer;
var
  rv:longword;
  bIn:array[0..1023] of CK_BYTE;
  bTemp:array[0..1023] of CK_BYTE;
  bOut:array[0..1023] of CK_BYTE;
  ulIn,ulOut,ulTemp:CK_ULONG;
  Mechanism:array[0..2] of CK_ULONG;
  bHint:array[0..2] of string;
  ckMechanism:CK_MECHANISM;
  Param:CK_RC2_CBC_PARAMS;
  sMsg:string;
  i,i0,ulEncrypted,ulDecrypt:CK_ULONG;
const
  iv:array[0..7] of CK_BYTE=(CK_BYTE('*'),CK_BYTE('2'),CK_BYTE('1'),CK_BYTE('0'),CK_BYTE('4'),CK_BYTE('z'),CK_BYTE('y'),CK_BYTE('b'));
  ulEnc1stPice=33;
  ulDec1stPice=11;
begin
  ZeroMemory(@bIn,1024);
  ZeroMemory(@bOut,1024);
  ZeroMemory(@bTemp,1024);
//  ulIn:=0;
  ulOut:=0;
  ulTemp:=0;
  Mechanism[0]:= CKM_RC2_CBC;
  Mechanism[1]:= CKM_RC2_ECB;
  Mechanism[2]:= CKM_RC2_CBC_PAD;
  bHint[0]:='CKM_RC2_CBC:';
  bHint[1]:='CKM_RC2_ECB:';
  bHint[2]:='CKM_RC2_CBC_PAD:';

  memo.Lines.Add('');
  memo.Lines.Add('RC2: C_EncryptUpdate/C_DecryptUpdate: ');
	for i:=0 to 2 do begin
		ulIn := 256;
		if( i = 2) then begin
			ulIn := 253;
    end;
		for i0 := 0 to ulIn-1 do
			bIn[i0] := CK_BYTE(i0);

    Memo.Lines.Add(bHint[i]);

    CopyMemory(@Param.iv,@iv, 8);
		Param.ulEffectiveBits := 16*8;
    //initialize encryption:
    ZeroMemory(@ckMechanism,sizeof(CK_MECHANISM));
    ckMechanism.mechanism:=Mechanism[i];
    ckMechanism.pParameter:=@Param;
    ckMechanism.ulParameterLen:=sizeof(CK_RC2_CBC_PARAMS);;
    
		memo.Lines.Add('Encrypting initialize...');
    rv:=C_EncryptInit(g_hSession,@ckMechanism,m_hKey);
    if(rv <> CKR_OK) then begin
      sMsg:=Format('Call C_EncryptInit error,error code:0x%.8x',[rv]);
      Memo.Lines.Add(sMsg);
      result:=-1;
      exit;
    end;

		ulEncrypted := 0;
		Memo.Lines.Add('Encrypt the message...');
    //get buffer's size.
		rv := C_EncryptUpdate(g_hSession, @bIn, ulEnc1stPice, nil, @ulTemp);
    if(rv <> CKR_OK) then begin
      sMsg:=Format('Call C_EncryptUpdate to get buffer size error,error code:0x%.8x',[rv]);
      Memo.Lines.Add(sMsg);
      result:=-2;
      exit;
    end;
		rv := C_EncryptUpdate(g_hSession, @bIn, ulEnc1stPice, @bTemp,@ulTemp);
    if(rv <> CKR_OK) then begin
      sMsg:=Format('Call C_EncryptUpdate to encrypt message error,error code:0x%.8x',[rv]);
      Memo.Lines.Add(sMsg);
      result:=-3;
      exit;
    end;

		ulEncrypted:=ulEncrypted+ulTemp;
		ulTemp := 0;

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
      sMsg:=Format('Call C_EncryptFinal to encrypt message error,errCode:0x%.8x',[rv]);
      Memo.Lines.Add(sMsg);
      result:=-6;
      exit;
    end;
		ulEncrypted:=ulEncrypted+ulTemp;
		ulTemp := 0;
		Memo.Lines.Add('Data encrypted: ');
		ShowData(bTemp, ulEncrypted,memo);

		Memo.Lines.Add('Decrypting initialize...');
		rv := C_DecryptInit(g_hSession,@ckMechanism, m_hKey);
    if(rv <> CKR_OK) then begin
      sMsg:=Format('Call C_DecryptInit error,error code:0x%.8x',[rv]);
      Memo.Lines.Add(sMsg);
      result:=-7;
      exit;
    end;

		Memo.Lines.Add('Decrypt the message.');
		//Get buffer's size:
		ulDecrypt := 0;
		rv :=C_DecryptUpdate(g_hSession, @bTemp, ulDec1stPice, nil, @ulOut);
    if(rv <> CKR_OK) then begin
      sMsg:=Format('Call C_DecryptUpdate to get buffer size error,error code:0x%.8x',[rv]);
      Memo.Lines.Add(sMsg);
      result:=-8;
      exit;
    end;
		rv :=  C_DecryptUpdate(g_hSession, @bTemp, ulDec1stPice, @bOut, @ulOut);
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
		ulOut:= 0;
		rv := C_DecryptFinal(g_hSession, @bOut[ulDecrypt], @ulOut);
    if(rv <> CKR_OK) then begin
      sMsg:=Format('Call C_DecryptFinal error,error code:%.8x',[rv]);
      Memo.Lines.Add(sMsg);
      result:=-12;
      exit;
    end;
		ulDecrypt:=ulDecrypt+ulOut;
		
		Memo.Lines.Add('Data decrypted: ');
		ShowData(bOut, ulDecrypt,memo);

		if(false = CompareMem(@bIn,@bOut, ulDecrypt)) then begin
      memo.Lines.Add('The decrypted data is not as same as the original!');
      result:=-13;
      exit;
    end
    else begin
      memo.Lines.Add('The decrypted data is as same as the original!');
    end;
    memo.Lines.Add('');
	end;
  result:=0;
  exit;
end;
//-----------------------------------------------------------------------
function CRC2Test.Test(memo:TMemo):integer;
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
//-----------------------------------------------------------------------
end.
