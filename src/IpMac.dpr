program IpMac;
//{$APPTYPE CONSOLE}
{$R WindowsXP.res}
{$R *.res}
uses
  KOL in '..\lib\kol\Kol.pas',          //使用Kol类库，要不这么个小程序300K别人还以为捆绑了流氓
  IpMacUnit,
  NetAPIUnit;

begin
  ApplicationRun;
end.

