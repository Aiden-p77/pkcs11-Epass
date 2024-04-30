unit SSF33Test;
{=========================================================================

	Copyright(C) Feitian Technologies Co., Ltd.
	All rights reserved.

FILE:
	SSF33Test.pas

DESC:
	implementation of the SSF33Test class.
=========================================================================}
interface
uses
   ShareMem,Windows, SysUtils,pkcs11,CommonFun,StdCtrls;
const
   SSF33_BLOCK_LEN=16;
   BLOCK_SIZE=20;
   DEC_BLOCK_SIZE=16;
type
  CSSF33Test=class
  public
    function Test(memo:TMemo):integer;
  private
    m_hKey:CK_ULONG;

  	function GenerateKey():integer;
	  function crypt_Single(memo:TMemo):integer;
	  function crypt_Update(memo:TMemo):integer;
end;
//-----------------------------------------------------------------------
implementation
function CSSF33Test.GenerateKey():integer;
var
  rv:longword;
  oClass:CK_OBJECT_CLASS;
  keyType:CK_KEY_TYPE;
  bTrue:CK_BBOOL;
  bFalse:CK_BBOOL;
  ulLen:CK_ULONG;
  ulCount:CK_ULONG;
  mechanism : CK_MECHANISM;
  Ssf33Tem:array[0..6] of CK_ATTRIBUTE;
begin
  oClass := CKO_SECRET_KEY;
  keyType:=CKK_SSF33;
  bTrue:=1;
  bFalse:=0;
  ulLen:=16;
  ulCount:=sizeof(Ssf33tem) div sizeof(CK_ATTRIBUTE);
  mechanism.mechanism:=CKM_SSF33_KEY_GEN;
  mechanism.pParameter:=nil;
  mechanism.ulParameterLen:=0;

  Ssf33Tem[0].attrtype:=CKA_CLASS;
  Ssf33Tem[0].pValue:=@oClass;
  Ssf33Tem[0].ulValueLen:=sizeof(CK_OBJECT_CLASS);

  Ssf33Tem[1].attrtype:=CKA_KEY_TYPE;
  Ssf33Tem[1].pValue:=@keyType;
  Ssf33Tem[1].ulValueLen:=sizeof(CK_KEY_TYPE);

  Ssf33Tem[2].attrtype:=CKA_TOKEN;
  Ssf33Tem[2].pValue:=@bFalse;
  Ssf33Tem[2].ulValueLen:=sizeof(CK_BBOOL);

  Ssf33Tem[3].attrtype:=CKA_PRIVATE;
  Ssf33Tem[3].pValue:=@bTrue;
  Ssf33Tem[3].ulValueLen:=sizeof(CK_BBOOL);

  Ssf33Tem[4].attrtype:=CKA_ENCRYPT;
  Ssf33Tem[4].pValue:=@bTrue;
  Ssf33Tem[4].ulValueLen:=sizeof(CK_BBOOL);

  Ssf33Tem[5].attrtype:=CKA_DECRYPT;
  Ssf33Tem[5].pValue:=@bTrue;
  Ssf33Tem[5].ulValueLen:=sizeof(CK_BBOOL);

  Ssf33Tem[6].attrtype:=CKA_VALUE_LEN;
  Ssf33Tem[6].pValue:=@ulLen;
  Ssf33Tem[6].ulValueLen:=sizeof(CK_ULONG);

  rv :=C_GenerateKey(g_hSession, @mechanism, @Ssf33tem, ulCount, @m_hKey);
  if(rv <> CKR_OK) then begin
    result:=-1;
    exit;
  end;
  result:=0;
  exit;

end;
//-------------------------------------------------------------------------
function CSSF33Test.crypt_Single(memo:TMemo):integer;
const
  iv:array[0..15] of CK_BYTE=(CK_BYTE('*'),CK_BYTE('2'),CK_BYTE('1'),CK_BYTE('0'),CK_BYTE('4'),CK_BYTE('z'),CK_BYTE('y'),CK_BYTE('b'),
                              CK_BYTE('*'),CK_BYTE('2'),CK_BYTE('1'),CK_BYTE('0'),CK_BYTE('4'),CK_BYTE('z'),CK_BYTE('y'),CK_BYTE('b'));
var
  rv:longword;
  i,i0,iStart,iStep:integer;
  ulIn,ulOut,ulTemp:CK_ULONG;
  bIn:array[0..1024*3-1] of CK_BYTE;
  bTemp:array[0..1024*3-1] of CK_BYTE;
  bOut:array[0..1024*3-1] of CK_BYTE;
  Mechanism:array[0..2] of CK_ULONG;
  bHint:array[0..2] of string;
  ckMechanism:CK_MECHANISM;
  sMsg:string;

begin

  ZeroMemory(@bIn,1024*3);
  ZeroMemory(@bTemp,1024*3);
  ZeroMemory(@bOut,1024*3);
	ulIn := 0;
  ulOut := 0;
  ulTemp := 0;

  Mechanism[0]:=CKM_SSF33_CBC;
  Mechanism[1]:=CKM_SSF33_ECB;
  Mechanism[2]:=CKM_SSF33_CBC_PAD;
  bHint[0]:='CKM_SSF33_CBC:';
  bHint[1]:='CKM_SSF33_ECB:';
  bHint[2]:='CKM_SSF33_CBC_PAD:';


  Memo.Lines.Add('SSF33: C_Encrypt/C_Decrypt:');
	for i:=0 to 2 do begin
		if(i=2) then begin
      iStart:=0;
      iStep:=1;
    end
    else begin
      iStart:=SSF33_BLOCK_LEN;
      iStep:=SSF33_BLOCK_LEN;
    end;
    ulIn:=iStart;
    while ulIn<32 do begin
      for i0:= 0 to ulIn-1 do begin
			  bIn[i0] := CK_BYTE(i0);
      end;

      Memo.Lines.Add('*	*	*	*	*	*	*	*	*	*	*');
      Memo.Lines.Add(bHint[i]);

      //initialize encryption:
      ZeroMemory(@ckMechanism,sizeof(CK_MECHANISM));
      ckMechanism.mechanism:=Mechanism[i];
      ckMechanism.pParameter:=@iv;
      ckMechanism.ulParameterLen:=16;

      Memo.Lines.Add('Encrypting initialize.');
      rv :=  C_EncryptInit(g_hSession, @ckMechanism, m_hKey);
      if(rv <> CKR_OK) then begin
        sMsg:=Format('Call C_EncryptInit error,errCode:0x%.8x',[rv]);
        Memo.Lines.Add(sMsg);
        result:=-1;
        exit;
      end;

      Memo.Lines.Add('Encrypt the message.');
      //Get the encrypted buffer's size:
      //If you do not declare the result's buffer previous,
      //you should invoke twice to get the buffer's size, such as:[Decrypt is similar]
      rv :=  C_Encrypt(g_hSession, @bIn, ulIn, nil, @ulTemp);
      if(rv <> CKR_OK) then begin
        sMsg:=Format('Call C_Encrypt to get buffer size error,errCode:0x%.8x',[rv]);
        Memo.Lines.Add(sMsg);
        result:=-2;
        exit;
      end;
      //encrypt data:
      rv := C_Encrypt(g_hSession, @bIn, ulIn, @bTemp, @ulTemp);
      if(rv <> CKR_OK) then begin
        sMsg:=Format('Call C_Encrypt to encrypt message error,errCode:0x%.8x',[rv]);
        Memo.Lines.Add(sMsg);
        result:=-3;
        exit;
      end;

      memo.Lines.Add('Data encrypted: ');
      ShowData(bTemp, ulTemp,memo);

      //initialize decryption
      memo.Lines.Add('Decrypting initialize.');
      rv :=C_DecryptInit(g_hSession, @ckMechanism, m_hKey);
      if(rv <> CKR_OK) then begin
        sMsg:=Format('Call C_DecryptInit error,errCode:0x%.8x',[rv]);
        Memo.Lines.Add(sMsg);
        result:=-4;
        exit;
      end;
      memo.Lines.Add('Decrypt the message.');
      //Get buffer's size:
      rv :=C_Decrypt(g_hSession, @bTemp, ulTemp, nil, @ulOut);
      if(rv <> CKR_OK) then begin
        sMsg:=Format('Call C_Decrypt to get buffer size error,errCode:0x%.8x',[rv]);
        Memo.Lines.Add(sMsg);
        result:=-5;
        exit;
      end;
      //Get decrypted data:
      rv := C_Decrypt(g_hSession, @bTemp, ulTemp, @bOut, @ulOut);
      if(rv <> CKR_OK) then begin
        sMsg:=Format('Call C_Decrypt to get decrypt message error,errCode:0x%.8x',[rv]);
        Memo.Lines.Add(sMsg);
        result:=-6;
        exit;
      end;

      memo.Lines.Add('Data decrypted: ');
      ShowData(bOut, ulOut,memo);

     //compare the original message and decrypted message
      memo.Lines.Add('Compare the original message and decrypted data: ');
      if(false =CompareMem(@bIn,@bOut,ulOut)) then begin
        Memo.Lines.Add('Decrypted data is not the same as the original');
        result:=-7;
        exit;
      end;
        inc(ulIn,iStep);
    end;

	end;
  Memo.Lines.Add('Decrypted data is as same as the original');
  result:=0;
  exit;
end;
//-------------------------------------------------------------------------
function CSSF33Test.crypt_Update(memo:TMemo):integer;
var
  rv:CK_RV;
  pRetData:CK_BYTE_PTR;
  bTemp:array[0..1024*3-1] of CK_BYTE;
  bIn:array[0..1024*3-1] of CK_BYTE;
  bOut:array[0..1024*3-1] of CK_BYTE;
  ulIn,ulOut,ulTemp,ulEncrypted,ulDecrypt:CK_ULONG;
  bHint:array[0..2] of string;
  ckMechanism:CK_MECHANISM;
  i,i0,ulLoop,ulLeft:longword;
  iStart,iStep:integer;
  sMsg:string;
const

  Mechanism:array[0..2] of CK_ULONG=(CKM_SSF33_CBC,CKM_SSF33_ECB,CKM_SSF33_CBC_PAD);
  iv:array[0..15] of CK_BYTE=(CK_BYTE('*'),CK_BYTE('2'),CK_BYTE('1'),CK_BYTE('0'),CK_BYTE('4'),CK_BYTE('z'),CK_BYTE('y'),CK_BYTE('b'),
                              CK_BYTE('*'),CK_BYTE('2'),CK_BYTE('1'),CK_BYTE('0'),CK_BYTE('4'),CK_BYTE('z'),CK_BYTE('y'),CK_BYTE('b'));

begin
  ZeroMemory(@bIn,1024*3);
  ZeroMemory(@bOut,1024*3);
  ZeroMemory(@bTemp,1024*3);
  ulIn:=0;
  ulOut:=0;
  ulTemp:=0;
	bHint[0] := 'CKM_SSF33_CBC: ';
  bHint[1] := 'CKM_SSF33_ECB: ';
  bHint[2] := 'CKM_SSF33_CBC_PAD: ';

	memo.Lines.Add('*	*	*	*	*	*	*	*	*	*	*	*	*	*	*	*');
	for i:=0 to 2 do begin
		if(i=2) then begin
      iStart:=0;
      iStep:=1;
    end
    else begin
      iStart:=SSF33_BLOCK_LEN;
      iStep:=SSF33_BLOCK_LEN;
    end;
    for ulIn:=iStart to 31 do begin
    
      for i0 := 0 to ulIn-1 do begin
        bIn[i0] := CK_BYTE(i0);
      end;

      memo.Lines.Add('SSF33: C_EncryptUpdate/C_DecryptUpdate: ');
      memo.Lines.Add(bHint[i]);
      //ecnrypt init:
      ckMechanism.mechanism:=Mechanism[i];
      ckMechanism.pParameter:=@iv;
      ckMechanism.ulParameterLen:=16;
      memo.Lines.Add('Encrypting initialize.');
      rv :=C_EncryptInit(g_hSession,@ckMechanism, m_hKey);
      if(rv <> CKR_OK) then begin
        sMsg:=Format('Call C_EncryptInit error,errCode:0x%.8x',[rv]);
        Memo.Lines.Add(sMsg);
        result:=-1;
        exit;
      end;

      ulEncrypted := 0;
      memo.Lines.Add('Encrypt the message.');
			ulLoop := ulIn div BLOCK_SIZE;
			ulLeft := ulIn mod BLOCK_SIZE;
			pRetData := @bTemp[0];
			for i0 := 0 to ulLoop-1 do begin
				rv :=C_EncryptUpdate(g_hSession, @bIn[BLOCK_SIZE * i0], BLOCK_SIZE, nil, @ulTemp);//get buffer's size.
        if(CKR_OK <> rv) then begin
          sMsg:= Format('Call C_EncryptUpdate[inside loop] to get buffersize error,errCode:0x%.8x',[rv]);
          memo.Lines.Add(sMsg);
          result:=-2;
          exit;
        end;
				rv :=C_EncryptUpdate(g_hSession, @bIn[BLOCK_SIZE * i0], BLOCK_SIZE, pRetData, @ulTemp);
        if(CKR_OK <> rv) then begin
          sMsg:= Format('Call C_EncryptUpdate[inside loop] to encrypt data error,errCode:0x%.8x',[rv]);
          memo.Lines.Add(sMsg);
          result:=-3;
          exit;
        end;
        inc(pRetData,ulTemp);
				ulEncrypted:=ulEncrypted+ulTemp;
			end;
			if(0 <> ulLeft) then begin
				rv := C_EncryptUpdate(g_hSession, @bIn[BLOCK_SIZE * i0], ulLeft, nil, @ulTemp);//get buffer's size.
        if(CKR_OK <> rv) then begin
          sMsg:= Format('Call C_EncryptUpdate[inside loop] to get buffer size,errCode:0x%.8x',[rv]);
          memo.Lines.Add(sMsg);
          result:=-4;
          exit;
        end;
				rv := C_EncryptUpdate(g_hSession, @bIn[BLOCK_SIZE * i0], ulLeft, pRetData, @ulTemp);
        if(CKR_OK <> rv) then begin
          sMsg:= Format('Call C_EncryptUpdate[inside loop] to encrypt data error,errCode:0x%.8x',[rv]);
          memo.Lines.Add(sMsg);
          result:=-5;
          exit;
        end;
				inc(pRetData,ulTemp);
				ulEncrypted:=ulEncrypted+ulTemp;
			end;
      memo.Lines.Add('C_EncryptFinal...');
      rv :=C_EncryptFinal(g_hSession, nil, @ulTemp);
      if(CKR_OK <> rv) then begin
        sMsg:= Format('Call C_EncryptFinal[inside loop] to get buffer size error,errCode:0x%.8x',[rv]);
        memo.Lines.Add(sMsg);
        result:=-6;
        exit;
      end;
      rv :=C_EncryptFinal(g_hSession, pRetData, @ulTemp);
      if(CKR_OK <> rv) then begin
        sMsg:= Format('Call C_EncryptFinal[inside loop] to encrypt error,errCode:0x%.8x',[rv]);
        memo.Lines.Add(sMsg);
        result:=-7;
        exit;
      end;
      ulEncrypted:=ulEncrypted+ulTemp;
      ulTemp := 0;
      memo.Lines.Add('Data encrypted: ');
      ShowData(bTemp, ulEncrypted,memo);

      memo.Lines.Add('Decrypting initialize.');

      rv :=C_DecryptInit(g_hSession, @ckMechanism, m_hKey);
      if(CKR_OK <> rv) then begin
        sMsg:= Format('Call C_DecryptInit error,errCode:0x%.8x',[rv]);
        memo.Lines.Add(sMsg);
        result:=-8;
        exit;
      end;
      memo.Lines.Add('Decrypt the message.');

      ulLoop := ulEncrypted div DEC_BLOCK_SIZE;
      pRetData := @bOut[0];
      ulDecrypt:= 0;
      for i0 := 0 to ulLoop-1 do begin
        rv := C_DecryptUpdate(g_hSession, @bTemp[DEC_BLOCK_SIZE * i0], DEC_BLOCK_SIZE, nil, @ulTemp);//get buffer's size.
        if(CKR_OK <> rv) then begin
          sMsg:= Format('Call C_DecryptUpdate to get buffer size error,errCode:0x%.8x',[rv]);
          memo.Lines.Add(sMsg);
          result:=-9;
          exit;
        end;
        rv := C_DecryptUpdate(g_hSession, @bTemp[DEC_BLOCK_SIZE * i0], DEC_BLOCK_SIZE, pRetData, @ulTemp);
        if(CKR_OK <> rv) then begin
          sMsg:= Format('Call C_DecryptUpdate to decrypt error,errCode:0x%.8x',[rv]);
          memo.Lines.Add(sMsg);
          result:=-10;
          exit;
        end;
        inc(pRetData,ulTemp);
        ulDecrypt:=ulDecrypt+ulTemp;
      end;
      memo.Lines.Add('C_DecryptFinal...');
      rv :=C_DecryptFinal(g_hSession, nil, @ulTemp);
      if(CKR_OK <> rv) then begin
        sMsg:= Format('Call C_DecryptFinal to get buffer size error,errCode:0x%.8x',[rv]);
        memo.Lines.Add(sMsg);
        result:=-11;
        exit;
      end;
      rv :=C_DecryptFinal(g_hSession, pRetData, @ulTemp);
      if(CKR_OK <> rv) then begin
        sMsg:= Format('Call C_DecryptUpdate to decrypt error,errCode:0x%.8x',[rv]);
        memo.Lines.Add(sMsg);
        result:=-12;
        exit;
      end;
      ulDecrypt:= ulDecrypt+ulTemp;
			
      memo.Lines.Add('Data decrypted: ');
      ShowData(bOut, ulDecrypt,memo);
			
      memo.Lines.Add('Compare the original message and decrypted data: ');
      if(not CompareMem(@bIn, @bOut, ulDecrypt)) then begin
        Memo.Lines.Add('Decrypted data is not the same as the original');
        result:=13;
        exit;
      end;
    end;
	end;
  Memo.Lines.Add('Decrypted data is the same as the original');
  result:=0;
  exit;
end;
//-----------------------------------------------------------------------
function CSSF33Test.Test(memo:TMemo):integer;
var
  iRet:integer;
begin
	GenerateKey();
  if(m_hKey=0) then begin
    result:=-1;
    exit;
  end;
	iRet:=crypt_Single(memo);
  if(iRet <> 0) then begin
    result:=-2;
    exit;
  end;
 	iRet:=crypt_Update(memo);
  if(iRet <> 0) then begin
    result:=-3;
    exit;
  end;
  result:=0;
  exit;
end;
//-----------------------------------------------------------------------
end.
