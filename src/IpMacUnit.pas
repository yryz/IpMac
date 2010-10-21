unit IpMacUnit;

interface
uses
  Windows,
  Messages,
  MySysutils,
  WinSock,
  KOL,
  NetAPIUnit,
  FuncLib;

const
  HELP_TEXT         = '	利用ARP请求原理及多线程扫描，可扫描所有IP设备!'#13#10#13#10
    + '1.[扫描线程] 若该IP段离线机器较多请将线程数增加，以提速．'#13#10#13#10
    + '  默认线程设为0,实际工作线程数等于IP数(但不大于1000,且“扫列表”时“设置”都无效).'#13#10#13#10
    + '2.[修改备注] 保存扫描列表后，直接用记事本编辑IpMac.txt。格式为 “IP=MAC|备注”';

procedure ApplicationRun;
implementation
const
  BTN_START         = '开始(&S)';
  BTN_STOP          = '停止(&S)';
  STATUS_NONE       = '?';
  STATUS_DOWN       = '×';
  STATUS_UP         = '√';
  MAC_YES           = 'Yes';
  MAC_NO            = 'No';
  MAC_NEW           = 'New';
  TITLE_SCAN        = '扫描';
  TITLE_WAKEUP      = '唤醒';
  TITLE_LOAD        = '载入';

var
  W                 : pControl;
  gSet              : pControl;
  iEdit1, iEdit2, iEdit3: pControl;
  Label1, chkScanList: pControl;
  StartBtn, ClearBtn: pControl;

  gScanList, g_ScanList: pControl;
  PopupMenu         : PMenu;

  g_Stop            : Boolean = True;   {停止}
  ThID              : DWORD;
  g_StartTick       : DWORD;            {计数器}
  g_StartIP         : DWORD;
  g_ScanCount       : DWORD;
  g_ThreadCount     : DWORD = 10;       //线程总数
  g_NrThreadActive  : Integer;          //线程退出就减一 ,全部退出则完成
  g_LvCri           : TRTLCriticalSection;
  isChange          : Boolean = false;
  isScanList        : Boolean;
  cfgFile, ipmacFile: string;

procedure MakeEnd(const Title: string; const Num: DWORD);
var
  Str               : string;
  i, n, j           : DWORD;
  dwStopTick        : DWORD;
begin
  j := 0;
  n := Num;
  g_Stop := true;
  StartBtn.Caption := BTN_START;
  dwStopTick := GetTickCount;
  if Title = TITLE_SCAN then
  begin
    if g_ScanList.Count > 0 then
      for i := 0 to g_ScanList.Count - 1 do
      begin
        if g_ScanList.LVItems[i, 4] <> STATUS_DOWN then
          Inc(n);
        if g_ScanList.LVItems[i, 2] <> '0' then
          Inc(j);
      end;
    Str := '　New: ' + IntToStr(j);
  end;
  W.Caption := Title + '耗时: ' + IntToStr(DiffTickCount(g_StartTick, dwStopTick))
    + ' ms　IP: ' + IntToStr(n) + '/' + IntToStr(g_ScanList.Count) + Str;
end;

function DoArpScan(dwIp: DWORD): Integer;
var
  nIndex            : Integer;
  sIP, sMac         : string;
begin
  Result := 0;
  sIP := HexToIp(IntToHex(dwIp, 8));
  sMac := GetMacAddr(dwIp);             //SendARP

  EnterCriticalSection(g_LvCri);        //进入临界区
  try
    W.Caption := sIP;                   //目前扫描的IP
    with g_ScanList^ do
    begin
      nIndex := LVIndexOf(sIP);
      if sMac <> '' then
      begin
        if nIndex > -1 then
        begin
          LVItems[nIndex, 2] := IntToStr(GetCurrentThreadId);
          if (LVItems[nIndex, 1] <> sMac) then
          begin
            isChange := True;
            LVItems[nIndex, 1] := sMac; //'网卡MAC码'
            LVItems[nIndex, 3] := MAC_YES
          end;
        end
        else
        begin                           //添加
          isChange := True;
          nIndex := LVItemAdd(sIP);     //'IP地址'
          LVItems[nIndex, 1] := sMac;   //'网卡MAC码'
          LVItems[nIndex, 2] := IntToStr(GetCurrentThreadId);
          LVItems[nIndex, 3] := MAC_NEW;
          LVItems[nIndex, 5] := '无';
        end;
        LVItems[nIndex, 4] := STATUS_UP;
        Result := 1;
      end
      else if nIndex > -1 then
        LVItems[nIndex, 4] := STATUS_DOWN;
    end;

    if isScanList then
    begin
      if g_NrThreadActive > 1 then
        Dec(g_NrThreadActive)
      else
      begin                             //自己是后最一个收尾线程
        MakeEnd(TITLE_SCAN, 0);
      end;
    end;

  finally
    LeaveCriticalSection(g_LvCri);      //退出临界区
  end;
end;

function ARPScanThread(dwIndex: DWORD): Integer;
var
  dwCurrIP, i, dwNum: DWORD;
begin
  Result := 0;
  dwNum := g_ScanCount div g_ThreadCount; //统一分任务
  if (g_ScanCount mod g_ThreadCount) >= dwIndex then //分剩下的任务
    Inc(dwNum);
  for i := 0 to dwNum - 1 do
  begin
    if g_Stop then
      Break;

    dwCurrIP := htonl(ntohl(g_StartIP) + i * g_ThreadCount + dwIndex - 1); //转换顺序 并加1
    Result := DoArpScan(dwCurrIP);
  end;

  EnterCriticalSection(g_LvCri);        //进入临界区
  try
    if g_NrThreadActive > 1 then
      Dec(g_NrThreadActive)
    else
    begin                               //自己是后最一个收尾线程
      MakeEnd(TITLE_SCAN, 0);
    end;
  finally
    LeaveCriticalSection(g_LvCri);      //退出临界区
  end;
end;

procedure StartScan;
var
  i, dwIP1, dwIP0   : DWORD;
  hexIP             : string;
begin
  if not isScanList then
  begin
    if (inet_addr(PChar(trim(iEdit1.Text))) <> INADDR_NONE) and
      (inet_addr(PChar(trim(iEdit1.Text))) <> INADDR_NONE) then
    begin
      hexIP := IntToHex(inet_addr(PChar(trim(iEdit1.Text))), 8); //01 00 A8 C0
      dwIP0 := InetHexToInt(hexIP);     {转换成为一个长整形数}
      iEdit1.Text := HexToIp(hexIP);    {允许输入 一个数值表示IP}

      hexIP := IntToHex(inet_addr(PChar(trim(iEdit2.Text))), 8); //01 00 A8 C0
      dwIP1 := InetHexToInt(hexIP);
      iEdit2.Text := HexToIp(hexIP);

      if dwIP1 > dwIP0 then
      begin
        g_ScanCount := dwIP1 - dwIP0 + 1;
        g_StartIP := inet_addr(PChar(trim(iEdit1.Text)));
        Label1.Caption := '++>';
        hexIP := IntToHex(inet_addr(PChar(iEdit1.Text)), 8); //01 00 A8 C0
      end
      else
      begin
        g_ScanCount := dwIP0 - dwIP1 + 1;
        g_StartIP := inet_addr(PChar(trim(iEdit2.Text)));
        Label1.Caption := '<++';
      end;
    end
    else
      Exit;
  end
  else
  begin
    g_ScanCount := g_ScanList.Count;
  end;

  g_ThreadCount := StrToInt(iEdit3.Text);

  if (g_ScanCount < g_ThreadCount) or (g_ThreadCount = 0) then
    g_ThreadCount := g_ScanCount;
  if g_ThreadCount > 1000 then
    g_ThreadCount := 800;
  g_NrThreadActive := g_ThreadCount;
  g_StartTick := GetTickCount;
  if not isScanList then
  begin
    for i := 1 to g_ThreadCount do
      CloseHandle(BeginThread(nil, 0, @ARPScanThread, Pointer(i), 0, ThID));
  end
  else
  begin
    for i := 0 to g_ScanCount - 1 do
      CloseHandle(BeginThread(nil, 0, @DoArpScan,
        Pointer(inet_addr(PChar(g_ScanList^.LVItems[I, 0]))), 0, ThID));
  end;
end;

procedure StartWakeUp;
var
  i, n              : Integer;
begin
  n := 0;
  g_Stop := false;
  StartBtn.Caption := BTN_STOP;
  g_StartTick := GetTickCount;
  with g_ScanList^ do
    if LVSelCount > 0 then
    begin
      i := LVCurItem;
      while i > -1 do
      begin
        if g_Stop then
          exit;
        W.Caption := LVItems[i, 0];
        WakeUpPro(LVItems[i, 1]);
        Inc(n);
        i := LVNextSelected(i);
        if iEdit3.Text <> '' then
          sleep(StrToInt(iEdit3.Text))
        else
          sleep(1);
      end;
    end;
  MakeEnd(TITLE_WAKEUP, n);
end;

procedure SaveList(Sender: PObj);
var
  i, id             : Integer;
  slList            : PStrList;
begin
  WritePrivateProfileString('set', 'startip', PChar(iEdit1.Text), PChar(cfgfile));
  WritePrivateProfileString('set', 'endip', PChar(iEdit2.Text), PChar(cfgfile));

  if ((g_ScanList.Count > 0) and isChange) or Assigned(Sender) then
  begin
    if not Assigned(Sender) then
      if Messagebox(W.Handle, '是否保存列表?', 'HOU提示', MB_YESNO
        + MB_ICONQUESTION) = IDNO then
        Exit;

    slList := NewStrList();
    slList^.NameDelimiter := '=';
    try
      if FileExists(ipmacFile) then
      begin
        id := Messagebox(W.Handle, 'IpMac列表已存在，[是]覆盖 [否]新增？',
          'HOU提示', MB_YESNOCANCEL + MB_ICONQUESTION);
        if id = ID_NO then
          slList^.LoadFromFile(ipmacFile);
      end;

      if id <> ID_CANCEL then
      begin
        with g_ScanList^ do
          for i := 0 to Count - 1 do
            slList^.Values[LVItems[i, 0]] := LVItems[i, 1] + '|' + LVItems[i, 5];
        slList^.SaveToFile(ipmacFile);
      end;
    finally
      slList^.Free;
    end;
  end;
  isChange := False;
end;

procedure LoadList(Sender: PObj);
var
  i                 : Integer;
  s                 : string;
  szBuf             : array[0..255] of char;
  nIndex            : Integer;
  slList            : PStrList;
begin                                   //载入
  if not Assigned(Sender) then
  begin
    GetPrivateProfileString('set', 'startip', '192.168.0.1', szBuf,
      SizeOf(szBuf), PChar(cfgfile));
    iEdit1.Text := szBuf;
    GetPrivateProfileString('set', 'endip', '192.168.0.254', szBuf,
      SizeOf(szBuf), PChar(cfgfile));
    iEdit2.Text := szBuf;
  end
  else if fileexists(ipmacFile) then
  begin
    slList := NewStrList();
    try
      g_StartTick := GetTickCount;
      slList^.NameDelimiter := '=';
      slList^.LoadFromFile(ipmacFile);
      with g_ScanList^ do
      begin
        Clear;
        for i := 0 to slList^.Count - 1 do
        begin
          nIndex := LVItemAdd(GetSubStrEx(slList^.Items[i], '', '=', s));
          LVItems[nIndex, 1] := GetSubStrEx(s, '', '|', s);
          LVItems[nIndex, 2] := '0';
          LVItems[nIndex, 3] := MAC_NO;
          LVItems[nIndex, 4] := STATUS_NONE;
          LVItems[nIndex, 5] := s;
        end;
        MakeEnd(TITLE_LOAD, 0);
      end;
    finally
      slList^.Free;
    end;
    isChange := False;
  end;
end;

procedure ShowHelp;
begin
  Messagebox(W.Handle, PChar(StrDec('BBDE5D804CCE3EFD43B40286514DA47582399378A740B57EBB04A058996452B060BA09EFDB19F03788268502E41AAA1EC050D07BDD08F04AB800A75F')
    + HELP_TEXT), '关于', 0);
end;

procedure OnListVPopup(Sender: PObj);
var
  CursorPos         : TPoint;
begin
  if g_ScanList.RightClick then
    if GetCursorPos(CursorPos) then
      PopupMenu.PopupEx(CursorPos.X, CursorPos.Y);
end;

procedure OnStartBtn(Sender: PObj);
begin
  if StartBtn.Caption = BTN_START then
  begin
    if isScanList then
      if g_ScanList^.Count = 0 then
        Exit;
    W.Caption := '初始化...';
    ClearAllArp();                      //清空ARP
    g_Stop := false;
    StartBtn.Caption := BTN_STOP;
    StartScan;
  end
  else
    g_Stop := true;
end;

procedure OnClearBtn(Sender: PObj);
begin
  g_ScanList.Clear;
end;

procedure OnChkScanList(Sender: PObj);
begin
  isScanList := not isScanList;         //pControl(Sender)^.SetChecked
end;

function OnFormMessage(dummy: Pointer; var Msg: TMsg; var Rslt: Integer): boolean;
begin
  result := false;
  case Msg.Message of
    WM_CLOSE:
      begin
        g_Stop := true;
        SaveList(nil);
      end;
    WM_HELP: ShowHelp;
  end;
end;

procedure OnPopupMenu(dummy: Pointer; Sender: PMenu; Item: Integer);
var
  i                 : Integer;
begin
  case Item of
    0: ShowHelp;
    2: if g_Stop and (g_ScanList.LVSelCount > 0) then
        BeginThread(nil, 0, @StartWakeUp, nil, 0, ThID);
    4: SaveList(Sender);
    6: LoadList(Sender);
    8: with g_ScanList^ do
        if LVSelCount > 0 then
          repeat
            i := LVCurItem;
            LVDelete(i);
          until i < 0;
    10: W.Close;
  end;
end;

procedure ScanSetControl;
begin
  gSet := NewGroupBox(W, 'IP范围 ／ 扫描线程　OR　唤醒延时').SetSize(100, 50);
  gSet.Align := caTop;

  Label1 := NewLabel(gSet, '++>').SetPosition(105, 25);
  with Label1^ do
  begin
    Width := 20;
    Font.Color := clBlue;
  end;

  iEdit1 := NewEditBox(gSet, []).SetPosition(8, 20);
  with iEdit1^ do
  begin
    Width := 95;
    Color := clWhite;
    //Text := '192.168.0.1';
  end;

  iEdit2 := NewEditBox(gSet, []).SetPosition(125, 20);
  with iEdit2^ do
  begin
    Width := 95;
    Color := clWhite;
    //Text := '192.168.0.254';
  end;

  iEdit3 := NewEditBox(gSet, []).SetPosition(223, 20);
  with iEdit3^ do
  begin
    Width := 30;
    TextAlign := taCenter;
    Color := clWhite;
    Text := '0';
  end;

  StartBtn := NewButton(gSet, BTN_START).SetPosition(258, 20);
  with StartBtn^ do
  begin
    Width := 55;
    OnClick := TOnEvent(MakeMethod(nil, @OnStartBtn));
  end;

  ClearBtn := NewButton(gSet, '清空(&C)').SetPosition(318, 20);
  with ClearBtn^ do
  begin
    Width := 55;
    OnClick := TOnEvent(MakeMethod(nil, @OnClearBtn));
  end;

  chkScanList := NewCheckbox(gSet, '扫列表').SetPosition(380, 20);
  with chkScanList^ do
  begin
    Width := 66;
    OnClick := TOnEvent(MakeMethod(nil, @OnChkScanList));
  end;
end;

procedure ScanListControl;
begin
  gScanList := NewGroupBox(W, '列表'
    + StrDec('9F249768AEBA73926D3310A42EC557858F349778BE40A96A8F34978364BF377DFA7DDE25A942AB10C57E840CE134FE69FC6CDE75AE50B96A9F'));
  gScanList.Align := caClient;

  g_ScanList := NewListView(gScanList, lvsDetail, [lvoGridLines,
    lvoRowSelect, lvoMultiselect, lvoHeaderDragDrop, lvoSortAscending], nil, nil, nil);
  with g_ScanList^ do
  begin
    OnClick := TOnEvent(MakeMethod(nil, @OnListVPopup));
    Align := caClient;
    LVColAdd('IP地址', taLeft, 105);
    LVColAdd('MAC地址', taLeft, 120);
    LVColAdd('线程', taCenter, 50);
    LVColAdd('变更', taCenter, 45);
    LVColAdd('状态', taCenter, 45);
    LVColAdd('备注', taCenter, 66);
    DoubleBuffered := True;
  end;
end;

procedure CreateControls;
begin
  ScanSetControl;
  ScanListControl;
  PopupMenu := newMenu(g_ScanList, 100, [], TOnMenuItem(MakeMethod(nil, @OnPopupMenu)));
  with PopupMenu^ do
  begin
    Insert(-1, '关于', nil, []);
    Insert(-1, '-', nil, [moSeparator]);
    Insert(-1, '唤醒', nil, []);
    Insert(-1, '-', nil, [moSeparator]);
    Insert(-1, '保存', nil, []);
    Insert(-1, '-', nil, [moSeparator]);
    Insert(-1, '载入', nil, []);
    Insert(-1, '-', nil, [moSeparator]);
    Insert(-1, '删除', nil, []);
    Insert(-1, '-', nil, [moSeparator]);
    Insert(-1, '退出', nil, []);
  end;
end;

procedure ApplicationRun;
begin
  Applet := newApplet('IP-MAC');
  Applet.ExStyle := 0;
  AppButtonUsed := true;
  W := newForm(Applet, 'IP-MAC扫描-网络唤醒 v1.2e').SetSize(480, 380);
  with W^ do
  begin
    Style := WS_OVERLAPPED + WS_CAPTION + WS_SYSMENU + WS_MINIMIZEBOX
      + WS_MAXIMIZEBOX + WS_THICKFRAME;
    CenterOnParent;
    OnMessage := TOnMessage(MakeMethod(nil, @OnFormMessage));
    Font.FontHeight := -12;
    Font.FontName:= '宋体';
  end;
  CreateControls;

  LoadList(nil);
  SetProcessWorkingSetSize(GetCurrentProcess, $FFFFFFFF, $FFFFFFFF);
  Run(Applet);                          //消息循环
  Applet.Free;
end;

initialization
  cfgfile := ExtractFilePath(ParamStr(0)) + 'IPMac.ini';
  ipmacFile := ExtractFilePath(ParamStr(0)) + 'IPMac.txt';
  InitializeCriticalSection(g_LvCri);
finalization
  DeleteCriticalSection(g_LvCri);

end.

