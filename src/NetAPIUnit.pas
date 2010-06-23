unit NetAPIUnit;

interface

uses
  Windows, MySysutils, Winsock, IpTypes;

type
  {ARP Addr行链表行}
  PMIB_IPADDRROW = ^MIB_IPADDRROW;
  MIB_IPADDRROW = record
    dwAddr: DWORD;
    dwIndex: DWORD;
    dwMask: DWORD;
    dwBCastAddr: DWORD;
    dwReasmSize: DWORD;
    unused1: WORD;
    unused2: WORD;
  end;
  PMIB_IPADDRTABLE = ^MIB_IPADDRTABLE;
  MIB_IPADDRTABLE = record
    dwNumEntries: DWORD;
    table: array[0..0] of MIB_IPADDRROW;
  end;

  {ARP 数据链表全}
  PMIB_IPNETROW = ^MIB_IPNETROW;
  MIB_IPNETROW = record
    dwIndex: DWORD;
    dwPhysAddrLen: DWORD;
    bPhysAddr: array[0..7] of Byte;
    dwAddr: DWORD;
    dwType: DWORD;
  end;


  {网络接口链表行}
  PMIB_IFROW = ^MIB_IFROW;
  MIB_IFROW = record
    wszName: array[0..255] of WCHAR;
    dwIndex: DWORD;
    dwType: DWORD;
    dwMtu: DWORD;
    dwSpeed: DWORD;
    dwPhysAddrLen: DWORD;
    bPhysAddr: array[0..7] of Byte;
    dwAdminStatus: DWORD;
    dwOperStatus: DWORD;
    dwLastChange: DWORD;
    dwInOctets: DWORD;
    dwInUcastPkts: DWORD;
    dwInNUcastPkts: DWORD;
    dwInDiscards: DWORD;
    dwInErrors: DWORD;
    dwInUnknownProtos: DWORD;
    dwOutOctets: DWORD;
    dwOutUcastPkts: DWORD;
    dwOutNUcastPkts: DWORD;
    dwOutDiscards: DWORD;
    dwOutErrors: DWORD;
    dwOutQLen: DWORD;
    dwDescrLen: DWORD;
    bDescr: array[0..255] of Byte;
  end;
  {网络接口链表全}
  PMIB_IFTABLE = ^MIB_IFTABLE;
  MIB_IFTABLE = record
    dwNumEntries: DWORD;
    table: array[0..0] of MIB_IFROW;
  end;

type
  {IP地址数组指针}
  TaPInAddr = array[0..10] of PInAddr;  //定义一个IN_ADDR类型的数组
  PaPInAddr = ^TaPInAddr;               //同上,用来得到本机的地址.

procedure SetArpEntry(const InetAddr, EtherAddr: string); {如果MAC为空，它将自动查询}
function GetMacAddr(const InetAddr: DWORD): string; {SendARP获取MAC地址}
procedure WakeUpPro(const MacAddr: string);
function HexToIp(Hex: string): string;  //16进制IP转.分式IP
function InetHexToInt(Hex: string): integer; //16进制IP转为网络顺序
//function GetHostCount(ip, mask: string): Cardinal;//取得当前网络最大主机数
function GetLocalIP: pchar;
function GetLocalNetArea(IP: integer): string;
function MakeID(ID: integer): string;   //IP不足补全
function ClearAllArp(): Integer;   //清空所有接口的ARP
implementation
const
  MIB_IF_TYPE_ETHERNET = 6;
  MIB_IF_TYPE_TOKENRING = 9;
  MIB_IPNET_TYPE_STATIC = 4;
  iphlpapilib       = 'iphlpapi.dll';

function SendARP(const DestIP, SrcIP: DWORD; pMacAddr: PULONG; var PhyAddrLen: ULONG): DWORD;
  stdcall; external iphlpapilib name 'SendARP';

function GetIfEntry(pIfRow: PMIB_IFROW): DWORD; stdcall; external iphlpapilib name 'GetIfEntry';

function GetIfTable(pIfTable: PMIB_IFTABLE; var pdwSize: ULONG; bOrder: BOOL): DWORD;
  stdcall; external iphlpapilib name 'GetIfTable';

function GetIpAddrTable(pIpAddrTable: PMIB_IPADDRTABLE; var pdwSize: ULONG; bOrder: BOOL): DWORD;
  stdcall; external iphlpapilib name 'GetIpAddrTable';

function SetIpNetEntry(const pArpEntry: MIB_IPNETROW): DWORD;
  stdcall; external iphlpapilib name 'SetIpNetEntry';

function DeleteIpNetEntry(const pArpEntry: MIB_IPNETROW): DWORD;
  stdcall; external iphlpapilib name 'DeleteIpNetEntry';

function FlushIpNetTable(dwIfIndex: DWORD): DWORD;
  stdcall; external iphlpapilib name 'FlushIpNetTable';

function GetAdaptersInfo(pAdapterInfo: PIP_ADAPTER_INFO; var pOutBufLen: ULONG): DWORD;
  stdcall; external iphlpapilib name 'GetAdaptersInfo';

type
  TPhysAddrByteArray = array[0..7] of Byte;


function HexToIp(Hex: string): string;  //00 11 22 33 TO 192.168.0.1
begin
  Result := IntToStr(StrToInt('$' + copy(Hex, 7, 2)))
    + '.' + IntToStr(StrToInt('$' + copy(Hex, 5, 2)))
    + '.' + IntToStr(StrToInt('$' + copy(Hex, 3, 2)))
    + '.' + IntToStr(StrToInt('$' + copy(Hex, 1, 2)));
end;

function InetHexToInt(Hex: string): integer; //00 11 22 33 TO 网络顺序 234216513
begin
  Result := StrToInt('$' + copy(Hex, 7, 2) + copy(Hex, 5, 2) + copy(Hex, 3, 2) + copy(Hex, 1, 2)); //==>02 00 A8 C0
end;

function GetLocalIP: pchar;
var
  Value             : TWSAData;
  buffer            : array[0..14] of Char;
begin
  WSAStartUp($0202, Value);
  getHostName(buffer, sizeof(buffer));  //用到用户名.PCHAR类
  Result := Inet_ntoa(PaPInAddr(GetHostByName(buffer).h_addr_list)[0]^); //用一个PAPINADDR类型转换.成in_addr数组指针
  WSACleanup;
end;

function GetLocalNetArea(IP: integer): string;
var
  Addr              : TinAddr;
begin
  Addr.S_addr := IP and inet_addr('255.255.255.0');
  Result := Inet_ntoa(Addr);
end;

function MakeID(ID: integer): string;
begin
  Result := IntToStr(ID mod 256);

  while length(Result) < 3 do
    Result := '0' + Result;

  case ID div 256 of
    1..255: Result := '.' + Result;
    256..65536: Result := '..' + Result;
  end
end;

procedure WakeUpPro(const MacAddr: string);
var
  WSAData           : TWSAData;
  MSocket           : TSocket;
  SockAddrIn        : TSockAddrIn;
  i                 : integer;
  MagicAddr         : array[0..5] of Byte;
  MagicData         : array[0..101] of Byte;
begin
  for i := 0 to 5 do MagicAddr[i] := StrToInt('$' + copy(MacAddr, i * 3 + 1, 2));
  try
    WSAStartUp($0101, WSAData);
    MSocket := Socket(AF_INET, SOCK_DGRAM, IPPROTO_IP); //创建一个UPD数据报SOCKET.
    if MSocket = INVALID_SOCKET then exit;
    i := 1;
    setsockopt(MSocket, SOL_SOCKET, SO_BROADCAST, pchar(@i), sizeof(i)); //设置广播
    FillChar(MagicData, sizeof(MagicData), $FF);
    i := 6;
    while i < sizeof(MagicData) do begin
      Move(MagicAddr, Pointer(Longint(@MagicData) + i)^, 6);
      Inc(i, 6);
    end;
    SockAddrIn.SIn_Family := AF_INET;
    SockAddrIn.SIn_Addr.S_addr := Longint(INADDR_BROADCAST);
    sendto(MSocket, MagicData, sizeof(MagicData), 0, SockAddrIn, sizeof(SockAddrIn));
    CloseSocket(MSocket);
    WSACleanup;
  except
    exit;
  end;
end;

function StringToPhysAddr(PhysAddrString: string): TPhysAddrByteArray;
var
  C                 : string;
  i, V              : integer;
begin
  PhysAddrString := UpperCase(PhysAddrString);
  for i := 0 to 5 do begin
    C := copy(PhysAddrString, i * 3 + 1, 2);
    V := StrToInt('$' + C);
    Result[i] := V;
  end;
end;

//------------------------------------------------------------------------------

// Returns the IP address table. The caller must free the memory.

function GetIpAddrTableWithAlloc: PMIB_IPADDRTABLE;
var
  Size              : ULONG;
begin
  Size := 0;
  GetIpAddrTable(nil, Size, True);
  Result := AllocMem(Size);
  if GetIpAddrTable(Result, Size, True) <> NO_ERROR then begin
    FreeMem(Result);
    Result := nil;
  end;
end;

function FirstNetworkAdapter(IpAddrTable: PMIB_IPADDRTABLE): integer;
var
  i                 : integer;
  IfInfo            : MIB_IFROW;
begin
  Result := -1;
  for i := 0 to IpAddrTable^.dwNumEntries - 1 do begin
{$R-}IfInfo.dwIndex := IpAddrTable^.table[i].dwIndex; {$R+}
    if GetIfEntry(@IfInfo) = NO_ERROR then begin
      if IfInfo.dwType in [MIB_IF_TYPE_ETHERNET, MIB_IF_TYPE_TOKENRING] then begin
        Result := IfInfo.dwIndex;
        Break;
      end;
    end;
  end;
end;

// Adds an entry to the ARP table.

procedure SetArpEntry(const InetAddr, EtherAddr: string); {如果MAC为空，它将自动查询}
var
  Entry             : MIB_IPNETROW;
begin
  FillChar(Entry, sizeof(Entry), 0);
  Entry.dwAddr := inet_addr(pchar(InetAddr));
  Entry.dwPhysAddrLen := 6;
  Entry.dwType := MIB_IPNET_TYPE_STATIC;
  Entry.dwIndex := FirstNetworkAdapter(GetIpAddrTableWithAlloc);
  if EtherAddr = '' then begin
    DeleteIpNetEntry(Entry);
    SendARP(Entry.dwAddr, 0, @Entry.bPhysAddr, Entry.dwPhysAddrLen); {取得MAC}
  end
  else
    TPhysAddrByteArray(Entry.bPhysAddr) := StringToPhysAddr(EtherAddr);
  SetIpNetEntry(Entry);
end;

function GetMacAddr(const InetAddr: DWORD): string;
var
  ulMACAddr         : array[0..5] of Byte;
  ulAddrLen         : ULONG;
  ulIPAddr          : DWORD;
  i                 : integer;
begin
  Result := '';
  ulIPAddr := InetAddr;
  ulAddrLen := sizeof(ulMACAddr);
  SendARP(ulIPAddr, 0, @ulMACAddr, ulAddrLen);
  for i := 0 to High(ulMACAddr) do
    if ulMACAddr[i] <> 0 then begin
      Result := IntToHex(ulMACAddr[0], 2) + '-' +
        IntToHex(ulMACAddr[1], 2) + '-' +
        IntToHex(ulMACAddr[2], 2) + '-' +
        IntToHex(ulMACAddr[3], 2) + '-' +
        IntToHex(ulMACAddr[4], 2) + '-' +
        IntToHex(ulMACAddr[5], 2);
      Break;
    end;
end;

function ClearAllArp(): Integer;
var
  Size              : DWORD;
  Adapters, Adapter : PIpAdapterInfo;
begin
  Size := 0;
  Result := 0;
  if GetAdaptersInfo(nil, Size) <> ERROR_BUFFER_OVERFLOW then Exit;
  Adapters := AllocMem(Size);
  try
    if GetAdaptersInfo(Adapters, Size) = NO_ERROR then begin
      Adapter := Adapters;
      while Adapter <> nil do begin
        FlushIpNetTable(Adapter.Index);
        Adapter := Adapter^.Next;
        inc(Result);
      end;
    end;
  finally
    FreeMem(Adapters);
  end;
end;

end.

