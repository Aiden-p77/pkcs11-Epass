unit RSATest;
{=========================================================================

	Copyright(C) Feitian Technologies Co., Ltd.
	All rights reserved.

FILE:
	rsatest.pas

DESC:
	implementation of the RSATest class.
=========================================================================}
interface
uses
   ShareMem,Windows, SysUtils,pkcs11,CommonFun,StdCtrls;
type
  CRSATest=class
  public
    function RSATest(memo:TMemo):Boolean;
  private
    function GenerageRsaKeyPair(memo:TMemo):integer;
    function SignMessage(memo:TMemo):integer;
    function VerifyMessage(memo:TMemo):integer;
    function EncryptMessage(memo:TMemo):integer;
    function DecryptMessage(memo:TMemo):integer;
end;
var
  keyType : CK_ULONG = CKK_RSA;
  subject : string = 'Sample RSA Key Pair';
  bTrue   : Boolean=TRUE;
  ulModulusBits : CK_ULONG = 1024;
  pEncryptedData: array[0..1023] of CK_BYTE;
  m_ulCipherLen:CK_ULONG;

  keyGenMechanism : CK_MECHANISM =( mechanism:CKM_RSA_PKCS_KEY_PAIR_GEN;  pParameter:nil;  ulParameterLen:0);
  ckMechanism : CK_MECHANISM = (mechanism:CKM_RSA_PKCS; pParameter:nil;   ulParameterLen:0);
  priClass : CK_OBJECT_CLASS = CKO_PRIVATE_KEY;
  pubClass : CK_OBJECT_CLASS = CKO_PUBLIC_KEY;
  hPubKey  : CK_OBJECT_HANDLE = 0;
  hPriKey	 : CK_OBJECT_HANDLE	= 0;

  sDataToSign  : string = 'UsbToken RunRsaKeyGenerationTest...';
  bSignatureBuffer : array[0..1023] of CK_BYTE;
  bEncryptedData: array[0..1023] of CK_BYTE;
	ulSignatureLen : CK_ULONG;
	pbCipherBuffer : CK_BYTE_PTR;
	ulCipherLen : CK_ULONG;

  priTemplate : array[0..8] of CK_ATTRIBUTE = (
	  (attrtype:CKA_CLASS;      pValue:@priClass;	ulValueLen:sizeof(priClass)),
	  (attrtype:CKA_KEY_TYPE;	  pValue:@keyType;  ulValueLen:sizeof(keyType)),
	  (attrtype:CKA_SUBJECT;    pValue:@subject;  ulValueLen:sizeof(subject)),
	  (attrtype:CKA_DECRYPT;	  pValue:@bTrue;		ulValueLen:sizeof(bTrue)),
	  (attrtype:CKA_PRIVATE;	  pValue:@bTrue;		ulValueLen:sizeof(bTrue)),
	  (attrtype:CKA_SENSITIVE;  pValue:@bTrue;		ulValueLen:sizeof(bTrue)),
	  (attrtype:CKA_TOKEN;		  pValue:@bTrue;		ulValueLen:sizeof(bTrue)),
	  (attrtype:CKA_EXTRACTABLE;pValue:@bTrue;		ulValueLen:sizeof(bTrue)),
	  (attrtype:CKA_UNWRAP;		  pValue:@bTrue;		ulValueLen:sizeof(bTrue))
    );

  pubTemplate : array[0..6] of CK_ATTRIBUTE = (
	(attrtype:CKA_CLASS;		    pValue:@pubClass;		    ulValueLen:sizeof(pubClass)),
	(attrtype:CKA_KEY_TYPE;		  pValue:@keyType;		    ulValueLen:sizeof(keyType)),
	(attrtype:CKA_SUBJECT;	    pValue:@subject;		    ulValueLen:sizeof(subject)),
	(attrtype:CKA_MODULUS_BITS;	pValue:@ulModulusBits;  ulValueLen:sizeof(ulModulusBits)),
	(attrtype:CKA_ENCRYPT;		  pValue:@bTrue;			    ulValueLen:sizeof(bTrue)),
	(attrtype:CKA_TOKEN;			  pValue:@bTrue;			    ulValueLen:sizeof(bTrue)),
	(attrtype:CKA_WRAP;			    pValue:@bTrue;			    ulValueLen:sizeof(bTrue))
  );

//-----------------------------------------------------------------------
implementation

function CRSATest.GenerageRsaKeyPair(memo:TMemo):integer;
var
  rv:CK_RV;
  ulPrivateKeyAttributeCount:CK_ULONG;
  ulPublicKeyAttributeCount:CK_ULONG;
  sMsg:string;
begin
  memo.Lines.Add('');
  memo.Lines.Add('Generating public/private key pair...');
  ulPublicKeyAttributeCount := sizeof(pubTemplate) div sizeof(CK_ATTRIBUTE);
  ulPrivateKeyAttributeCount:= sizeof(priTemplate) div sizeof(CK_ATTRIBUTE);

  rv := C_GenerateKeyPair(g_hSession,@keyGenMechanism,
                          @pubTemplate, ulPublicKeyAttributeCount,
                          @priTemplate, ulPrivateKeyAttributeCount,
                          @hPubKey, @hPriKey);
  if(rv <> CKR_OK) then begin
    sMsg:=Format('Failed to Call C_GenerateKeyPair, error code:0x%.8x',[rv]);
    memo.Lines.Add(sMsg);
    result:=-1;
    exit;
  end;
  memo.Lines.Add('Generating public/private key pair ok!');
  result:=0;
  exit;
end;
//-----------------------------------------------------------------------
function CRSATest.SignMessage(memo:TMemo):integer;
var
  rv:CK_RV;
  sMsg:string;
  ulDataToSignLen : CK_ULONG;

begin
  ulDataToSignLen:=Length(sDataToSign);
  ulSignatureLen:=0;
  ZeroMemory(@bSignatureBuffer,1024);

  memo.Lines.Add('');

  memo.Lines.Add('Sign initialize...');
  rv := C_SignInit(g_hSession, @ckMechanism, hPriKey);
  if(CKR_OK <> rv) then begin
		sMsg := Format('Failed to call C_SignInit failed! Error code: 0x%.8x.',[rv]);
    Memo.Lines.Add(sMsg);
    result:=-1;
    exit
  end;


  memo.Lines.Add('Sign the message...');
  rv := C_Sign(g_hSession,@sDataToSign[1],ulDataToSignLen,nil, @ulSignatureLen);
  if(CKR_OK <> rv) then begin
		sMsg := Format('Call C_Sign to get buffer size error! Error Code: 0x%.8x.',[rv]);
    Memo.Lines.Add(sMsg);
    result:=-2;
    exit
  end;
  rv := C_Sign(g_hSession,@sDataToSign[1],ulDataToSignLen,@bSignatureBuffer[0], @ulSignatureLen);
	if(CKR_OK <> rv) then begin
		sMsg := Format('Call C_Sign to sign data error!! Error Code: 0x%.8x.',[rv]);
    Memo.Lines.Add(sMsg);
    result:=-3;
    exit
  end;
  memo.Lines.Add('The message to be signed is:');
  memo.Lines.Add(sDataToSign);
  memo.Lines.Add('Signed message is:');
  ShowData(bSignatureBuffer,ulSignatureLen,memo);
  result:=0;
  exit;
end;
//-----------------------------------------------------------------------
function CRSATest.VerifyMessage(memo:TMemo):integer;
var
  rv:CK_RV;
  sMsg:string;
  ulDataLen:longword;
begin
  memo.Lines.Add('');
  memo.Lines.Add('Verify initialize...');
	rv := C_VerifyInit(g_hSession, @ckMechanism,hPubKey);
	if(CKR_OK <> rv) then begin
    sMsg:= Format('Failed to call VerifyInit! Error code: 0x%.8x',[rv]);
    Memo.Lines.Add(sMsg);
    result:=-1;
		exit;
	end;
  ulDataLen:= Length(sDataToSign);
	rv := C_Verify(g_hSession,@sDataToSign[1], ulDataLen,@bSignatureBuffer[0],ulSignatureLen);
	if(CKR_OK <> rv) then begin
    sMsg:=Format('Failed to call verify! Error code: 0x%.8x.',[rv]);
		Memo.Lines.Add(sMsg);
    result:=-2;
    exit;
  end
	else
		Memo.Lines.Add('Verify Successfully!');
    result:=0;
    exit;
end;
//-----------------------------------------------------------------------
function CRSATest.EncryptMessage(memo:TMemo):integer;
var
  rv:CK_RV;
  sMsg:string;
  arrDataToEncrypt : array of byte;
  dataLen:longword;
begin
  dataLen:=Length(sDataToSign);
  SetLength(arrDataToEncrypt,dataLen+1);
  ZeroMemory(arrDataToEncrypt,dataLen+1);
  CopyMemory(arrDataToEncrypt, @sDataToSign[1],dataLen);
  
  memo.Lines.Add('');
  memo.Lines.Add('The message to be encrypted in string mode: ');
  memo.Lines.Add(sDataToSign);
  memo.Lines.Add('The message to be encrypted in hex mode:');
  ShowData(arrDataToEncrypt,dataLen,memo);

  memo.Lines.Add('Encrypt initialize...');
	rv := C_EncryptInit(g_hSession,@ckMechanism,hPubKey);
	if(CKR_OK <> rv) then begin
    sMsg:=Format('Failed to call EncryptInit! Error code: 0x%.8x.',[rv]);
		Memo.Lines.Add(sMsg);
    result:=-1;
    exit;
	end;

  memo.Lines.Add('Encrypt the message...');
	rv := C_Encrypt(g_hSession, @arrDataToEncrypt, dataLen, nil, @ulCipherLen);
	if(CKR_OK <> rv) then begin
    sMsg:=Format('Can not acquire the size of Data After encrypt! Error code: 0x%.8x.',[rv]);
    Memo.Lines.Add(sMsg);
    result:=-2;
		exit;
 	end;

	ZeroMemory(@bEncryptedData, 1024);

 	rv := C_Encrypt(g_hSession, @arrDataToEncrypt[0], dataLen, @bEncryptedData[0], @ulCipherLen);
	if (CKR_OK <> rv) then begin
    sMsg:=Format('Failed to encrypt! Error code: 0x%.8x',[rv]);
		Memo.Lines.Add(sMsg);
    result:=-3;
		exit;
	end;
  Memo.Lines.Add('Encryted Data is:');
  ShowData(bEncryptedData,ulCipherLen,memo);
  result:=0;
  exit;

end;
//-----------------------------------------------------------------------
function CRSATest.DecryptMessage(memo:TMemo):integer;
var
  bRestoredMsg:array[0..1023] of char;
  ulRestoredMsgLen:CK_ULONG;
  rv:CK_RV;
  sMsg:string;
begin

	rv := C_DecryptInit(g_hSession,@ckMechanism, hPriKey);
	if(CKR_OK <> rv) then begin
		sMsg:=Format('Failed to call DecryptInit! Error code 0x%.8x.',[rv]);
    Memo.Lines.Add(sMsg);
    result:=-1;
    exit;
	end;

	rv := C_Decrypt(g_hSession, @bEncryptedData,  ulCipherLen, nil, @ulRestoredMsgLen);
	if(CKR_OK <> rv) then begin
    sMsg:=Format('Can not acuire size of Data after Decrypt! Error code 0x%.x.',[rv]);
		Memo.Lines.Add(sMsg);
    result:=-1;
    exit;
	end;

	ZeroMemory(@bRestoredMsg,1024);
	rv := C_Decrypt(g_hSession, @bEncryptedData, ulCipherLen, @bRestoredMsg[0], @ulRestoredMsgLen);
	if (CKR_OK <> rv) then begin
    sMsg:=Format('Failed to call decrypt, Error code 0x%.8x.',[rv]);
    Memo.Lines.Add(sMsg);
    result:=-2;
    exit;
	end;
  Memo.Lines.Add('Decrypted Data is :');
  Memo.Lines.Add(string(bRestoredMsg));
  result:=0;
  exit;

end;
//-----------------------------------------------------------------------

function CRSATest.RSATest(memo:TMemo):Boolean;
var
  iRet:integer;

begin
  iRet:=GenerageRsaKeyPair(memo);
  if(iRet <> 0) then begin
    result:=false;
    exit;
  end;
  iRet:=SignMessage(memo);
  if(iRet <> 0) then begin
    C_DestroyObject(g_hSession,hPubKey);
    C_DestroyObject(g_hSession,hPriKey);
    result:=false;
    exit;
  end;
  iRet:=VerifyMessage(memo);
  if(iRet<>0) then begin
    C_DestroyObject(g_hSession,hPubKey);
    C_DestroyObject(g_hSession,hPriKey);
    result:=false;
    exit;
  end;

  iRet:=EncryptMessage(memo);
  if(iRet <> 0) then begin
    C_DestroyObject(g_hSession,hPubKey);
    C_DestroyObject(g_hSession,hPriKey);
    result:=false;
    exit;
  end;
  iRet:=DecryptMessage(memo);
  if(iRet <> 0) then begin
    C_DestroyObject(g_hSession,hPubKey);
    C_DestroyObject(g_hSession,hPriKey);
    result:=false;
    exit;
  end;
  C_DestroyObject(g_hSession,hPubKey);
  C_DestroyObject(g_hSession,hPriKey);
  result:=true;
  exit;
end;

//-----------------------------------------------------------------------
end.
