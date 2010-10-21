unit MakeIcon;

interface
uses
  windows, kol;

function CreateDigitalIcon(value: integer): HIcon;

implementation

function CreateDigitalIcon(value: integer): HIcon;
const
  ASize             = 16;
var
  IconInfo          : TIconInfo;
  ARect             : TRect;
  SCreenDC, DCMask, DCColor: HDC;
  S                 : KolString;
  TextColor         : ColorRef;
begin
  S := Int2Str(Value);
  ARect := MakeRect(0, 0, ASize, ASize);
  with IconInfo do
  begin
    ScreenDC := GetDC(0);
    DCColor := CreateCompatibleDC(0);
    hbmColor := SelectObject(DCColor, CreateCompatibleBitmap(ScreenDC, ASize, ASize));
    ReleaseDC(0, SCreenDC);
    SelectObject(DCColor, GetStockObject(DEFAULT_GUI_FONT));
    SetBkColor(DCColor, $0);
    if Value < 40 then
      SetTextColor(DCColor, $008000)
    else if Value < 50 then
      SetTextColor(DCColor, $FF0000)
    else
      SetTextColor(DCColor, $0000FF);
    DrawText(DCColor, PkolChar(S), -1, ARect, DT_CENTER or DT_VCENTER or DT_SINGLELINE);

    DCMask := CreateCompatibleDC(0);
    hbmMask := SelectObject(DCMask, CreateBitmap(ASize, ASize, 1, 1, nil));
    SelectObject(DCMask, GetStockObject(DEFAULT_GUI_FONT));
    SetBKColor(DCMask, $FFFFFF);
    SetTextColor(DCMask, $0);
    patBlt(DCMask, 0, 0, ASize, ASize, WHITENESS);
    DrawText(DCMask, PkolChar(S), -1, ARect, DT_CENTER or DT_VCENTER or DT_SINGLELINE);

    fIcon := TRUE;
    xHotspot := 0;
    yHotspot := 0;
    hbmMask := SelectObject(DCMask, hbmMask);
    hbmColor := SelectObject(DCColor, hbmColor);
    Result := CreateIconIndirect(IconInfo);

    DeleteObject(hbmColor);
    DeleteObject(hbmMask);
    DeleteDC(DCColor);
    DeleteDC(DCMask);
    S := '';
  end;
end;
end.

