object FrmMain: TFrmMain
  Left = 356
  Top = 142
  BorderStyle = bsDialog
  Caption = 'PKCS Test for epass3003'
  ClientHeight = 506
  ClientWidth = 744
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'MS Sans Serif'
  Font.Style = []
  OldCreateOrder = False
  OnClose = FormClose
  OnShow = FormShow
  PixelsPerInch = 96
  TextHeight = 13
  object GroupBox1: TGroupBox
    Left = 6
    Top = 4
    Width = 185
    Height = 493
    Caption = 'Operations'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'MS Sans Serif'
    Font.Style = [fsBold]
    ParentFont = False
    TabOrder = 0
    object ButtDes: TButton
      Left = 18
      Top = 164
      Width = 150
      Height = 30
      Caption = 'DES'
      Enabled = False
      TabOrder = 0
      OnClick = ButtDesClick
    end
    object ButtDes3: TButton
      Left = 18
      Top = 209
      Width = 150
      Height = 30
      Caption = 'DES3'
      Enabled = False
      TabOrder = 1
      OnClick = ButtDes3Click
    end
    object ButtRC2: TButton
      Left = 18
      Top = 255
      Width = 150
      Height = 30
      Caption = 'RC2'
      Enabled = False
      TabOrder = 2
      OnClick = ButtRC2Click
    end
    object ButtRC4: TButton
      Left = 18
      Top = 300
      Width = 150
      Height = 30
      Caption = 'RC4'
      Enabled = False
      TabOrder = 3
      OnClick = ButtRC4Click
    end
    object ButtRSA: TButton
      Left = 18
      Top = 348
      Width = 150
      Height = 30
      Caption = 'RSA'
      Enabled = False
      TabOrder = 4
      OnClick = ButtRSAClick
    end
    object ButtExit: TButton
      Left = 18
      Top = 445
      Width = 150
      Height = 30
      Caption = 'Exit'
      TabOrder = 5
      OnClick = ButtExitClick
    end
    object ButtConnectTk: TButton
      Left = 18
      Top = 26
      Width = 150
      Height = 30
      Caption = 'Connect to Token'
      TabOrder = 6
      OnClick = ButtConnectTkClick
    end
    object ButtLogin: TButton
      Left = 18
      Top = 71
      Width = 150
      Height = 30
      Caption = 'Login'
      Enabled = False
      TabOrder = 7
      OnClick = ButtLoginClick
    end
  end
  object GroupBox2: TGroupBox
    Left = 198
    Top = 4
    Width = 539
    Height = 493
    Caption = 'Message'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'MS Sans Serif'
    Font.Style = [fsBold]
    ParentFont = False
    TabOrder = 1
    object Memo: TMemo
      Left = 2
      Top = 64
      Width = 535
      Height = 425
      Align = alCustom
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clWindowText
      Font.Height = -13
      Font.Name = 'MS Sans Serif'
      Font.Style = []
      ParentFont = False
      ReadOnly = True
      ScrollBars = ssBoth
      TabOrder = 0
    end
    object ButtClearMsg: TButton
      Left = 408
      Top = 19
      Width = 120
      Height = 30
      Caption = 'Clear Message'
      TabOrder = 1
      OnClick = ButtClearMsgClick
    end
  end
end
