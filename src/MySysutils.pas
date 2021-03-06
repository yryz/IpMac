unit MySysutils;

interface

uses
  Windows;

type
  TFileName = type string;

  TSearchRec = record
    Time: Integer;
    Size: Integer;
    Attr: Integer;
    Name: TFileName;
    ExcludeAttr: Integer;
    FindHandle: THandle platform;
    FindData: TWin32FindData platform;
  end;

  LongRec = packed record
    case Integer of
      0: (Lo, Hi: Word);
      1: (Words: array[0..1] of Word);
      2: (Bytes: array[0..3] of Byte);
  end;

  TMbcsByteType = (mbSingleByte, mbLeadByte, mbTrailByte);

  TSysCharSet = set of Char;

var
  LeadBytes         : set of Char = [];

const
  { File attribute constants }
  faReadOnly        = $00000001 platform;
  faHidden          = $00000002 platform;
  faSysFile         = $00000004 platform;
  faVolumeID        = $00000008 platform;
  faDirectory       = $00000010;
  faArchive         = $00000020 platform;
  faSymLink         = $00000040 platform;
  faAnyFile         = $0000003F;

  { File open modes }
  fmOpenRead        = $0000;
  fmOpenWrite       = $0001;
  fmOpenReadWrite   = $0002;

  fmShareCompat     = $0000 platform;   // DOS compatibility mode is not portable
  fmShareExclusive  = $0010;
  fmShareDenyWrite  = $0020;
  fmShareDenyRead   = $0030 platform;   // write-only not supported on all platforms
  fmShareDenyNone   = $0040;

  //Caption := Format2('你叫%s?有%d岁了吧?你知道%s是谁吗?', ['HouSoft', 20, '我']);
function Format2(const Format: string; const Args: array of const): string; //不支持浮点  20100313 Hou
function FloatToStr2(const f: Double; const N: Integer): string;

function Max(A, B: Integer): Integer;
function Min(A, B: Integer): Integer;
function AllocMem(Size: Cardinal): Pointer;
function StrLen(const Str: PChar): Cardinal;
function Trim(const S: string): string;
function TrimLeft(const S: string): string;
function UpperCase(const S: string): string;
function CharPos(const C: Char; const aSource: string): Integer;
function StringReplaceA(const S, OldPattern, NewPattern: string): string;
function StrPas(const Str: PChar): string;
function StrLCopy(Dest: PChar; const Source: PChar; MaxLen: Cardinal): PChar;
function StrPCopy(Dest: PChar; const Source: string): PChar;
function StrLIComp(const Str1, Str2: PChar; MaxLen: Cardinal): Integer; assembler;
function StrToBool(S: string): Boolean;
function BoolToStr(B: Boolean): string;
function IntToStr(Value: Integer): string;
function StrToInt(const S: string): Integer;
function IntToHex(Value: Integer; Digits: Integer): string;
function DiskSize(Drive: Byte): Int64;
function DirectoryExists(const Directory: string): Boolean;
function FileExists(const FileName: string): Boolean;
function ExtractFilePath(path: string): string;
function ExtractFilename(const FileName: string): string;
function DeleteFile(const FileName: string): Boolean;
function RenameFile(const OldName, NewName: string): Boolean;
function FindFirst(const path: string; Attr: Integer; var f: TSearchRec): Integer;
function FindNext(var f: TSearchRec): Integer;
procedure FindClose(var f: TSearchRec);
procedure FreeAndNil(var Obj);

function FindCmdLineSwitch(const Switch: string; const Chars: TSysCharSet;
  IgnoreCase: Boolean): Boolean;
//20100317
function FileCreate(const FileName: string): Integer;
function FileWrite(Handle: Integer; const Buffer; Count: LongWord): Integer;
function FileOpen(const FileName: string; Mode: LongWord): Integer;
function FileRead(Handle: Integer; var Buffer; Count: LongWord): Integer;
procedure FileClose(Handle: Integer);
implementation

function Format2(const Format: string; const Args: array of const): string;
var
  I                 : Integer;
  szBuf             : array[0..1024] of Char;
  Arglist           : array of Pointer;
begin
  Result := '';
  if Length(Args) > 0 then begin
    for I := 0 to High(Args) do begin
      SetLength(Arglist, Length(Arglist) + 1);
      Arglist[High(Arglist)] := Args[I].VPointer;
    end;

    wvsprintf(@szBuf, PChar(Format), PChar(Arglist));
    Result := szBuf;
  end;
end;

function FloatToStr2(const f: Double; const N: Integer): string; //<== 20100313 hou
var
  I, J, k           : Integer;
begin
  J := 1;
  for I := 1 to N do
    J := J * 10;

  k := Trunc(f);
  Result := IntToStr(k) + '.' + IntToStr(Trunc((f - k) * J));
end;


function Max(A, B: Integer): Integer;
begin
  if A > B then
    Result := A
  else
    Result := B;
end;

function Min(A, B: Integer): Integer;
begin
  if A < B then
    Result := A
  else
    Result := B;
end;

function AllocMem(Size: Cardinal): Pointer;
begin
  GetMem(Result, Size);
  FillChar(Result^, Size, 0);
end;

function StrLen(const Str: PChar): Cardinal; assembler;
asm
  MOV     EDX,EDI
  MOV     EDI,EAX
  MOV     ECX,0FFFFFFFFH
  XOR     AL,AL
  REPNE   SCASB
  MOV     EAX,0FFFFFFFEH
  SUB     EAX,ECX
  MOV     EDI,EDX
end;

function Trim(const S: string): string;
var
  I, L              : Integer;
begin
  L := Length(S);
  I := 1;
  while (I <= L) and (S[I] <= ' ') do
    Inc(I);
  if I > L then
    Result := ''
  else
  begin
    while S[L] <= ' ' do
      Dec(L);
    Result := Copy(S, I, L - I + 1);
  end;
end;

function TrimLeft(const S: string): string;
var
  I, L              : Integer;
begin
  L := Length(S);
  I := 1;
  while (I <= L) and (S[I] <= ' ') do Inc(I);
  Result := Copy(S, I, Maxint);
end;

function UpperCase(const S: string): string;
var
  Ch                : Char;
  L                 : Integer;
  Source, Dest      : PChar;
begin
  L := Length(S);
  SetLength(Result, L);
  Source := Pointer(S);
  Dest := Pointer(Result);
  while L <> 0 do
  begin
    Ch := Source^;
    if (Ch >= 'a') and (Ch <= 'z') then Dec(Ch, 32);
    Dest^ := Ch;
    Inc(Source);
    Inc(Dest);
    Dec(L);
  end;
end;

function CharPos(const C: Char; const aSource: string): Integer;
var
  L                 : Integer;
begin
  L := Length(aSource);
  Result := 0;
  if L = 0 then Exit;
  asm
      PUSH EDI                 //Preserve this register
      mov  EDI, aSource        //Point EDI at aSource
      mov  ECX, L              //Make a note of how many chars to search through
      mov  AL,  C              //and which char we want
    @Loop:
      mov  AH, [EDI]
      inc  EDI
      xor  AH, AL
      jz   @Found
      dec  ECX
      jnz  @Loop
      jmp  @NotFound
    @Found:
      sub  EDI, aSource        //EDI has been incremented, so EDI-OrigAdress = Char pos !
      mov  Result,   EDI
      jmp @TheEnd
    @NotFound:
      mov  Result, 0 // fix (ozz)
    @TheEnd:
      POP  EDI
  end;
end;

function StringReplaceA(const S, OldPattern, NewPattern: string): string;
var
  SearchStr, Patt, NewStr: string;
  Offset            : Integer;
begin
  SearchStr := UpperCase(S);
  Patt := UpperCase(OldPattern);
  NewStr := S;
  Result := '';
  while SearchStr <> '' do
  begin
    Offset := Pos(Patt, SearchStr);
    if Offset = 0 then
    begin
      Result := Result + NewStr;
      Break;
    end;
    Result := Result + Copy(NewStr, 1, Offset - 1) + NewPattern;
    NewStr := Copy(NewStr, Offset + Length(OldPattern), Maxint);
    SearchStr := Copy(SearchStr, Offset + Length(Patt), Maxint);
  end;
end;

function StrPas(const Str: PChar): string;
begin
  Result := Str;
end;

function StrLCopy(Dest: PChar; const Source: PChar; MaxLen: Cardinal): PChar; assembler;
asm
        PUSH    EDI
        PUSH    ESI
        PUSH    EBX
        MOV     ESI,EAX
        MOV     EDI,EDX
        MOV     EBX,ECX
        XOR     AL,AL
        TEST    ECX,ECX
        JZ      @@1
        REPNE   SCASB
        JNE     @@1
        INC     ECX
@@1:    SUB     EBX,ECX
        MOV     EDI,ESI
        MOV     ESI,EDX
        MOV     EDX,EDI
        MOV     ECX,EBX
        SHR     ECX,2
        REP     MOVSD
        MOV     ECX,EBX
        AND     ECX,3
        REP     MOVSB
        STOSB
        MOV     EAX,EDX
        POP     EBX
        POP     ESI
        POP     EDI
end;

function StrPCopy(Dest: PChar; const Source: string): PChar;
begin
  Result := StrLCopy(Dest, PChar(Source), Length(Source));
end;

function StrLIComp(const Str1, Str2: PChar; MaxLen: Cardinal): Integer; assembler;
asm
        PUSH    EDI
        PUSH    ESI
        PUSH    EBX
        MOV     EDI,EDX
        MOV     ESI,EAX
        MOV     EBX,ECX
        XOR     EAX,EAX
        OR      ECX,ECX
        JE      @@4
        REPNE   SCASB
        SUB     EBX,ECX
        MOV     ECX,EBX
        MOV     EDI,EDX
        XOR     EDX,EDX
@@1:    REPE    CMPSB
        JE      @@4
        MOV     AL,[ESI-1]
        CMP     AL,'a'
        JB      @@2
        CMP     AL,'z'
        JA      @@2
        SUB     AL,20H
@@2:    MOV     DL,[EDI-1]
        CMP     DL,'a'
        JB      @@3
        CMP     DL,'z'
        JA      @@3
        SUB     DL,20H
@@3:    SUB     EAX,EDX
        JE      @@1
@@4:    POP     EBX
        POP     ESI
        POP     EDI
end;

function StrToBool(S: string): Boolean;
begin
  if S = '0' then Result := False
  else Result := True;
end;

function BoolToStr(B: Boolean): string;
begin
  if B then
    Result := '1'
  else
    Result := '0';
end;

procedure CvtInt;
asm
        OR      CL,CL
        JNZ     @CvtLoop
@C1:    OR      EAX,EAX
        JNS     @C2
        NEG     EAX
        CALL    @C2
        MOV     AL,'-'
        INC     ECX
        DEC     ESI
        MOV     [ESI],AL
        RET
@C2:    MOV     ECX,10

@CvtLoop:
        PUSH    EDX
        PUSH    ESI
@D1:    XOR     EDX,EDX
        DIV     ECX
        DEC     ESI
        ADD     DL,'0'
        CMP     DL,'0'+10
        JB      @D2
        ADD     DL,('A'-'0')-10
@D2:    MOV     [ESI],DL
        OR      EAX,EAX
        JNE     @D1
        POP     ECX
        POP     EDX
        SUB     ECX,ESI
        SUB     EDX,ECX
        JBE     @D5
        ADD     ECX,EDX
        MOV     AL,'0'
        SUB     ESI,EDX
        JMP     @z
@zloop: MOV     [ESI+EDX],AL
@z:     DEC     EDX
        JNZ     @zloop
        MOV     [ESI],AL
@D5:
end;

procedure CvtIntW;
asm
        OR      CL,CL
        JNZ     @CvtLoop
@C1:    OR      EAX,EAX
        JNS     @C2
        NEG     EAX
        CALL    @C2
        MOV     AX,'-'
        MOV     [ESI-2],AX
        SUB     ESI, 2
        INC     ECX
        RET
@C2:    MOV     ECX,10

@CvtLoop:
        PUSH    EDX
        PUSH    ESI
@D1:    XOR     EDX,EDX
        DIV     ECX
        ADD     DX,'0'
        SUB     ESI,2
        CMP     DX,'0'+10
        JB      @D2
        ADD     DX,('A'-'0')-10
@D2:    MOV     [ESI],DX
        OR      EAX,EAX
        JNE     @D1
        POP     ECX
        POP     EDX
        SUB     ECX,ESI
        SHR     ECX, 1
        SUB     EDX,ECX
        JBE     @D5
        ADD     ECX,EDX
        SUB     ESI,EDX
        MOV     AX,'0'
        SUB     ESI,EDX
        JMP     @z
@zloop: MOV     [ESI+EDX*2],AX
@z:     DEC     EDX
        JNZ     @zloop
        MOV     [ESI],AX
@D5:
end;

function IntToStr(Value: Integer): string;
//  FmtStr(Result, '%d', [Value]);
asm
        PUSH    ESI
        MOV     ESI, ESP
        SUB     ESP, 16
        XOR     ECX, ECX       // base: 0 for signed decimal
        PUSH    EDX            // result ptr
        XOR     EDX, EDX       // zero filled field width: 0 for no leading zeros
        CALL    CvtInt
        MOV     EDX, ESI
        POP     EAX            // result ptr
        CALL    System.@LStrFromPCharLen
        ADD     ESP, 16
        POP     ESI
end;

function StrToInt(const S: string): Integer;
var
  E                 : Integer;
begin
  Val(S, Result, E);
end;

function IntToHex(Value: Integer; Digits: Integer): string;
//  FmtStr(Result, '%.*x', [Digits, Value]);
asm
        CMP     EDX, 32        // Digits < buffer length?
        JBE     @A1
        XOR     EDX, EDX
@A1:    PUSH    ESI
        MOV     ESI, ESP
        SUB     ESP, 32
        PUSH    ECX            // result ptr
        MOV     ECX, 16        // base 16     EDX = Digits = field width
        CALL    CvtInt
        MOV     EDX, ESI
        POP     EAX            // result ptr
        CALL    System.@LStrFromPCharLen
        ADD     ESP, 32
        POP     ESI
end;

function InternalGetDiskSpace(Drive: Byte; var TotalSpace, FreeSpaceAvailable: Int64): Bool;
var
  RootPath          : array[0..4] of Char;
  RootPtr           : PChar;
begin
  RootPtr := nil;
  if Drive > 0 then
  begin
    RootPath[0] := Char(Drive + $40);
    RootPath[1] := ':';
    RootPath[2] := '\';
    RootPath[3] := #0;
    RootPtr := RootPath;
  end;
  Result := GetDiskFreeSpaceEx(RootPtr, FreeSpaceAvailable, TotalSpace, nil);
end;

function DiskSize(Drive: Byte): Int64;
var
  FreeSpace         : Int64;
begin
  if not InternalGetDiskSpace(Drive, Result, FreeSpace) then
    Result := -1;
end;

function DirectoryExists(const Directory: string): Boolean;
var
  Code              : Integer;
begin
  Code := GetFileAttributes(PChar(Directory));
  Result := (Code <> -1) and (FILE_ATTRIBUTE_DIRECTORY and Code <> 0);
end;

function FileAge(const FileName: string): Integer;
var
  Handle            : THandle;
  FindData          : TWin32FindData;
  LocalFileTime     : TFileTime;
begin
  Handle := FindFirstFile(PChar(FileName), FindData);
  if Handle <> INVALID_HANDLE_VALUE then
  begin
    Windows.FindClose(Handle);
    if (FindData.dwFileAttributes and FILE_ATTRIBUTE_DIRECTORY) = 0 then
    begin
      FileTimeToLocalFileTime(FindData.ftLastWriteTime, LocalFileTime);
      if FileTimeToDosDateTime(LocalFileTime, LongRec(Result).Hi, LongRec(Result).Lo) then Exit;
    end;
  end;
  Result := -1;
end;

function FileExists(const FileName: string): Boolean;
begin
  Result := FileAge(FileName) <> -1;
end;

function ExtractFilePath(path: string): string;
var
  I                 : Integer;
begin
  I := Length(path);
  while I >= 1 do
  begin
    if (path[I] = '\') or (path[I] = '/') or (path[I] = ':') then Break;
    Dec(I);
  end;
  Result := Copy(path, 1, I);
end;

function ExtractFilename(const FileName: string): string;
var
  I                 : Integer;
begin
  I := Length(FileName);
  while I >= 1 do
  begin
    if (FileName[I] = '/') or (FileName[I] = '\') or (FileName[I] = ':') then
    begin
      Result := Copy(FileName, I + 1, Maxint);
      Exit;
    end;
    Dec(I);
  end;
  Result := FileName;
end;

function DeleteFile(const FileName: string): Boolean;
begin
  Result := Windows.DeleteFile(PChar(FileName));
end;

function RenameFile(const OldName, NewName: string): Boolean;
begin
  Result := MoveFile(PChar(OldName), PChar(NewName));
end;

function FindMatchingFile(var f: TSearchRec): Integer;
var
  LocalFileTime     : TFileTime;
begin
  with f do
  begin
    while FindData.dwFileAttributes and ExcludeAttr <> 0 do
      if not FindNextFile(FindHandle, FindData) then
      begin
        Result := GetLastError;
        Exit;
      end;
    FileTimeToLocalFileTime(FindData.ftLastWriteTime, LocalFileTime);
    FileTimeToDosDateTime(LocalFileTime, LongRec(Time).Hi,
      LongRec(Time).Lo);
    Size := FindData.nFileSizeLow;
    Attr := FindData.dwFileAttributes;
    Name := FindData.cFileName;
  end;
  Result := 0;
end;

function FindFirst(const path: string; Attr: Integer; var f: TSearchRec): Integer;
const
  faSpecial         = faHidden or faSysFile or faVolumeID or faDirectory;
begin
  f.ExcludeAttr := not Attr and faSpecial;
  f.FindHandle := FindFirstFile(PChar(path), f.FindData);
  if f.FindHandle <> INVALID_HANDLE_VALUE then
  begin
    Result := FindMatchingFile(f);
    if Result <> 0 then FindClose(f);
  end else
    Result := GetLastError;
end;

function FindNext(var f: TSearchRec): Integer;
begin
  if FindNextFile(f.FindHandle, f.FindData) then
    Result := FindMatchingFile(f)
  else
    Result := GetLastError;
end;

procedure FindClose(var f: TSearchRec);
begin
  if f.FindHandle <> INVALID_HANDLE_VALUE then
  begin
    Windows.FindClose(f.FindHandle);
    f.FindHandle := INVALID_HANDLE_VALUE;
  end;
end;

procedure FreeAndNil(var Obj);
var
  Temp              : TObject;
begin
  Temp := TObject(Obj);
  Pointer(Obj) := nil;
  Temp.Free;
end;

function FindCmdLineSwitch(const Switch: string; const Chars: TSysCharSet; //<==20100313 hou
  IgnoreCase: Boolean): Boolean;
var
  I                 : Integer;
  S                 : string;
begin
  for I := 1 to ParamCount do
  begin
    S := ParamStr(I);
    if (Chars = []) or (S[1] in Chars) then
      if IgnoreCase then
      begin
        if Copy(S, 2, Maxint) = Switch then
        begin
          Result := True;
          Exit;
        end;
      end
      else begin
        if Copy(S, 2, Maxint) = Switch then
        begin
          Result := True;
          Exit;
        end;
      end;
  end;
  Result := False;
end;

function FileCreate(const FileName: string): Integer;
{$IFDEF MSWINDOWS}
begin
  Result := Integer(CreateFile(PChar(FileName), GENERIC_READ or GENERIC_WRITE,
    0, nil, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0));
end;
{$ENDIF}
{$IFDEF LINUX}
begin
  Result := FileCreate(FileName, FileAccessRights);
end;
{$ENDIF}

function FileWrite(Handle: Integer; const Buffer; Count: LongWord): Integer;
begin
{$IFDEF MSWINDOWS}
  if not WriteFile(THandle(Handle), Buffer, Count, LongWord(Result), nil) then
    Result := -1;
{$ENDIF}
{$IFDEF LINUX}
  Result := __write(Handle, Buffer, Count);
{$ENDIF}
end;

function FileOpen(const FileName: string; Mode: LongWord): Integer;
{$IFDEF MSWINDOWS}
const
  AccessMode        : array[0..2] of LongWord = (
    GENERIC_READ,
    GENERIC_WRITE,
    GENERIC_READ or GENERIC_WRITE);
  ShareMode         : array[0..4] of LongWord = (
    0,
    0,
    FILE_SHARE_READ,
    FILE_SHARE_WRITE,
    FILE_SHARE_READ or FILE_SHARE_WRITE);
begin
  Result := -1;
  if ((Mode and 3) <= fmOpenReadWrite) and
    ((Mode and $F0) <= fmShareDenyNone) then
    Result := Integer(CreateFile(PChar(FileName), AccessMode[Mode and 3],
      ShareMode[(Mode and $F0) shr 4], nil, OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL, 0));
end;
{$ENDIF}

function FileRead(Handle: Integer; var Buffer; Count: LongWord): Integer;
begin
{$IFDEF MSWINDOWS}
  if not ReadFile(THandle(Handle), Buffer, Count, LongWord(Result), nil) then
    Result := -1;
{$ENDIF}
{$IFDEF LINUX}
  Result := __read(Handle, Buffer, Count);
{$ENDIF}
end;

procedure FileClose(Handle: Integer);
begin
{$IFDEF MSWINDOWS}
  CloseHandle(THandle(Handle));
{$ENDIF}
{$IFDEF LINUX}
  __close(Handle);                      // No need to unlock since all locks are released on close.
{$ENDIF}
end;

end.
