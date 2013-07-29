{

Krypto - a file encrypter/decrypter based on the Frog algorithm.

Copyright (c) 2001 Daniel de Kok. All rights reserved.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

$Id: krypto.pas,v 1.4 2001/09/15 16:32:44 danieldk Exp $

}

Program Krypto;

uses FrogCrypt, Crt;

Const Key_Return = char(13);
Const Key_Backspace = char(8);

(* Print error and quit, shouldn't be in here *)
procedure Error(description : string);
begin
        WriteLn('Error: ', description);
        Halt(1);
end;

procedure EncryptFile(infilename : string; outfilename : string; binarykey : tBinaryKey);
var IV, plain, crypted : tMaxBuffer;
    cipher : cipherInstance;
    key : keyInstance;
    infile, outfile : file;
    buf, cbuf : tbuf;
    i, bytesread, byteswritten : longint;
    tmp: Word;
    x, y : byte;
begin
        // Open infile and outfile
        Assign(infile, infilename);
        Reset(infile,1);
        if IOResult <> 0 then Error('Cannot read input file!');
        Assign(outfile, outfilename);
        Rewrite(outfile,1);
        if IOResult <> 0 then Error('Cannot write output file!');

        // Get cursor coordinates
        x := WhereX; y := WhereY;

        // Prepare for encryption
        for i:=0 to blockSize-1 do IV[i]:=i+11;
        cipherInit(cipher, MODE_CBC, IV, blocksize);
        makeKey(key,DIR_ENCRYPT,keyLen,binaryKey,blockSize);

        // Read, encrypt and write
        repeat
                GotoXY(x, y);
                write(Round((FilePos(infile) / FileSize(infile)) * 100), '%');

                BlockRead(infile, buf, SizeOf(Buf), bytesread);
                EncryptBuf(cipher, key, buf, cbuf);
                BlockWrite(outfile, cbuf, SizeOf(buf), byteswritten);          // Add check for byteswritten
        until bytesread <> SizeOf(Buf);

        // Now we have to add a descriptive block...
        tmp := bytesread;
        plain[0] := hi(tmp);
        plain[1] := lo(tmp);
        blockEncrypt(cipher, key, plain, blockSize, crypted);
        Blockwrite(outfile, crypted, blocksize, byteswritten);

        close(infile);
        close(outfile);
end;

procedure DecryptFile(infilename : string; outfilename: string; binarykey : tBinaryKey);
var IV, plain, crypted : tMaxBuffer;
    cipher : cipherInstance;
    key : keyInstance;
    infile, outfile : file;
    buf, cbuf : tbuf;
    bytesread, byteswritten, i, filelen : longint;
    tmp : Word;
    hibyte, lobyte, x, y : Byte;
begin
        // Open infile and outfile
        Assign(infile, infilename);
        Reset(infile,1);
        if IOResult <> 0 then Error('Cannot read infile!');
        Assign(outfile, outfilename);
        Rewrite(outfile,1);
        if IOResult <> 0 then Error('Cannot write outfile!');
        filelen := FileSize(infile);

        // Get cursor position
        x := WhereX; y:= WhereY;

        // Prepare for dencryptrion
        for i := 0 to blockSize - 1 do IV[i] := i + 11;
        cipherInit(cipher, MODE_CBC, IV, blocksize);
        makeKey(key, DIR_DECRYPT, keyLen, binaryKey, blockSize);

        // Read, decrypt and write, except for last 'sizeof(cbuf) block' and 'blocksize block'
        for i := 1 to ((filelen div sizeof(cbuf))-1) do
        begin
                GotoXY(x, y);
                write(Round((FilePos(infile) / FileSize(infile)) * 100), '%');

                BlockRead(infile, cbuf, SizeOf(cBuf), bytesread);
                DecryptBuf(cipher, key, cbuf, buf);
                BlockWrite(outfile, buf, SizeOf(cbuf), byteswritten);          // Add check for byteswritten
        end;

        // Now read last block and decrypt it
        BlockRead(infile, cbuf, SizeOf(cBuf), bytesread);
        DecryptBuf(cipher, key, cbuf, buf);

        // Read descriptive info and decrypt it
        BlockRead(infile, crypted, blocksize, bytesread);
        blockDecrypt(cipher, key, crypted, blockSize, plain);

        // Now we can determine original file lenght and write away plaintext in buf.
        hibyte := plain[0]; lobyte := plain[1];
        tmp := MergeBytes(hibyte, lobyte);
        if tmp > sizeof(cbuf) then error('Decryption error!');
        BlockWrite(outfile, buf, tmp, byteswritten);

        close(infile);
        close(outfile);
end;

function StringToBinKey(instring : string) : tBinaryKey;
var i : integer;
begin
        // First copy contents of string to block
        for i:=0 to Length(instring)-1 do
        begin
                StringToBinKey[i] := byte(instring[i+1]);
        end;

        // If length of the string < keylen fill up remaining space
        if Length(instring) < keylen then
        for i := length(instring) + 1 to keylen do
        begin
                StringToBinKey[i-1] := 0;
        end;
end;

function GetKey : TBinaryKey;
var temp : tBinaryKey;
    i, count : integer;
    key : char;
    finished : boolean;
begin
        write('Password: ');
        // Empty temporary password block
        for i:= 0 to keylen-1 do temp[i] := 0;

        finished := false;
        count := 0;
        while not finished do
        begin
                key := ReadKey;
                case key of
                        Key_Return: finished := true;
                        Key_Backspace:
                        begin
                                if count > 0 then
                                begin
                                        Dec(count);
                                        temp[count] := 0;
                                end;
                        end;
                        else
                        begin
                                temp[count] := Byte(Key);
                                Inc(count);
                                if count > keylen-1 then finished := true;
                        end;
                end;
        end;
        GetKey := temp;
        writeln;
        writeln;
end;


procedure ShowHeader;
begin
        writeln('Krypto 0.41, copyright (c)2001-2003 Daniel de Kok');
        writeln('Max. key length: ', keylen * 8, '-bit');
        writeln;
end;

procedure ShowHelp;
begin
        writeln('Syntax:');
        writeln;
        writeln('Encryption: krypto -e <infile> <outfile> [key]');
        writeln('Decryption: krypto -d <infile> <outfile> [key]');
end;

var BinaryKey : tBinaryKey;
    firstparam : string;
begin
        ShowHeader;
        firstparam := ParamStr(1);
        if firstparam[2] = 'h' then
        begin
                ShowHelp;
                Halt(0);
        end;
        if ParamCount < 3 then Error('Incorrect number of parameters! Type "krypto -h" for help.');
        if ParamCount > 4 then Error('Incorrect number of parameters! Type "krypto -h" for help.');
        if ParamStr(2) = ParamStr(3) then Error('Input file and output file cannot be the same!');
        case firstparam[2] of
                'e':
                begin
                        if ParamCount = 3 then BinaryKey := GetKey
                        else
                        begin
                                if Length(ParamStr(4)) > keylen then Error('Key is too long!');
                                BinaryKey := StringToBinKey(ParamStr(4));
                        end;
                        write('Encrypting... ');
                        Encryptfile(ParamStr(2), ParamStr(3), BinaryKey);
                        WriteLn(' Done!');
                end;
                'd':
                begin
                        if ParamCount = 3 then BinaryKey := GetKey
                        else
                        begin
                                if Length(ParamStr(4)) > keylen then Error('Key is too long!');
                                BinaryKey := StringToBinKey(ParamStr(4));
                        end;
                        write('Decrypting... ');
                        Decryptfile(ParamStr(2), ParamStr(3), BinaryKey);
                        WriteLn(' Done!');
                end;
                else Error('Incorrect parameter! Type "krypto -h" for help.');
        end;
end.
