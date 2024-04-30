unit Frm_Login;

interface

uses
  SysUtils, Types, Classes, Variants, QTypes, QGraphics, QControls, QForms, 
  QDialogs, QStdCtrls;

type
  TFrmLogin = class(TForm)
    EditPin: TEdit;
    Label1: TLabel;
    ButtOk: TButton;
    ButtCancel: TButton;
    Label2: TLabel;
    procedure ButtCancelClick(Sender: TObject);
    procedure ButtOkClick(Sender: TObject);
    procedure EditPinKeyPress(Sender: TObject; var Key: Char);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  FrmLogin: TFrmLogin;
  g_strUserPin: string;

implementation

{$R *.xfm}

//------------------------------------------------------------------------
procedure TFrmLogin.ButtCancelClick(Sender: TObject);
begin
  g_strUserPin:='';
  Close();
end;

//------------------------------------------------------------------------
procedure TFrmLogin.ButtOkClick(Sender: TObject);
begin
  g_strUserPin:= EditPin.Text;
  Close();
end;
//------------------------------------------------------------------------
procedure TFrmLogin.EditPinKeyPress(Sender: TObject; var Key: Char);
begin
  if(Key=#13) then begin
    ButtOkClick(Sender);
  end;
end;

end.
