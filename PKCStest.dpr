program PKCStest;

uses
  ShareMem,
  Forms,
  MainFrm in 'MainFrm.pas' {FrmMain},
  Frm_Login in 'Frm_Login.pas' {FrmLogin},
  pkcs11 in 'pkcs11\pkcs11.pas',
  Des3test in 'Des3test.pas',
  CommonFun in 'CommonFun.pas',
  DesTest in 'DesTest.pas',
  RC2Test in 'RC2Test.pas',
  RC4Test in 'RC4Test.pas',
  RSATest in 'RSATest.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TFrmMain, FrmMain);
  Application.Run;
end.
