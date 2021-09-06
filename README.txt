created Nov.1 2006	H.H


Make
====

本プログラムは Linux上で動作を確認しています。
ファイルを解凍したら、
Makeコマンドでプログラムをコンパイルしてください。


設定ファイルの編集
==================
設定ファイルは、sipd.confです。
（例）
#sipd Version 1.1
USER            05088640025
DOMAIN        	acme.com 
HOSTID         	192.168.0.1 
HOSTPORT        5060
PROXY          	10.10.10.1 
PROXYPORT       5060
LOGINID        	********* 
PASSWORD       	********* 
RTPPORT         10001



①USERとDOMAIN
ここには、本UAのSIP-URIを指定します。例では
<sip:05088640025@acme.com>
となります。
②HOSTIDとHOSTPORT
ここには、このプログラムを動作させるマシンのIPアドレスと
SIP用に使用するUDPポート番号を指定します。
③PROXYとPROXYPORT
ここには、REGISTERするSIPサーバのIPアドレスとUDPポート
番号を指定します。
④LOGINIDとPASSWORD
REGISTERするときに要求されるIDとパスワードを設定します。
⑤RTPPORT
音声データを受け取るためのRTPPORT番号を指定します。ここで
指定された番号が、受信したINVITEに対する200OKに含まれる
SDPの中にセットされます。



音声ファイルの差し替え
======================
送信されるガイダンスの音声ファイルの差し替えが可能です。
各場面で使用される音声とファイル名の対応は
play.hに定義されています。
ファイル名を変更する場合には、このヘッダファイルを
編集した後に再コンパイルが必要です。

#define ROOM_INI        "./sd/room_ini.wav"
#define ROOM_SEL        "./sd/room_sel.wav"
#define ROOM_ENTER      "./sd/room_enter.wav"
#define ROOM_DECLINE    "./sd/room_decline.wav"
#define ROOM_NEW        "./sd/room_new.wav"
#define ROOM_ADD        "./sd/room_add.wav"
#define BGM             "./sd/bgm.wav"

ROOM_INI       	 着信直後に送られる音声です
ROOM_SEL    	会議室番号の入力を促します
ROOM_ENTER	会議室に入室できたことを告げます
ROOM_DECLINE	入室ができなかったことを告げます
ROOM_NEW	新しく会議室が作成されたことを通知します
ROOM_ADD	会議中に新しくメンバーが追加されたことを通知します
BGM		会議室作成後に流れるBGMです


動作の確認
==========
このプログラムはデーモンとして作成されていません。
コマンドとして起動してください。長時間動作させる
場合には、バックグラウンドジョブとして起動させて
ください。
起動コマンドは
$sipc
です。ユーパユーザで起動する必要はありません。
コマンド起動すると、処理待ちとなります。終了する場合には
起動端末からコントロールCするか、killシグナルを
送ってください。

起動すると、処理状況が標準出力に出力されます。

正常に起動すると以下のメッセージが出力されます。
------
Receive Thread started
Transmit Thread started
------
この後、本プログラムは設定されたSIPサーバにREGISTERを
試みます。REGISTERが成功すると以下のメッセージが出力
されます。
------
REGISTER OK
------
この後、INVITE待ち状態になります。INVITEを受信すると
以下のメッセージは出力されて、ガイダンス音声を送って
いることが表示されます。
------
INVITE From:0352122101
Reply 200 Romote RTP IP :219.105.174.27  Port:11196
RTP:219.105.174.27(464415195) PORT:11196
Guidance Thread started
Recpt thread treats 0352122101 call
------
端末から切断されると以下のメッセージが出力されます。
------
BYE From: 0352122101
------



