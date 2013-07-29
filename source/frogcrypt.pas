Unit FrogCrypt;

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

$Id: frogcrypt.pas,v 1.5 2001/08/17 22:37:12 danieldk Exp $

}

interface

Uses Crt;

const
   MIN_BLOCK_SIZE   =    8; (* [bytes] = 64 bits *)
   MAX_BLOCK_SIZE   =  128; (* [bytes] = 1024 bits *)
   MIN_KEY_SIZE     =    5; (* [bytes] = 40 bits *)
   MAX_KEY_SIZE     =  125; (* [bytes] = 1000 bits *)
   DIR_ENCRYPT =         0; (*  Are we encrypting?  *)
   DIR_DECRYPT =         1; (*  Are we decrypting?  *)

   numIter          =    8; (* number of iterations in main cycle *)
   maxInternalKeySize = numIter * (2*MAX_BLOCK_SIZE+256);

const blocksize = 16;
      keylen = 32;              // Increase this const if you want support for larger key, max. is 125 (1000-bit)
      bufsize = 4096;

type
   tBuffer=array[0..$FFF0] of byte; (* general purpose byte array;
       will be used for plaintext, ciphertext, IV, xorBu, substPermu,
       bombPermu, etc. *)
   tBinaryKey=array[0..MAX_KEY_SIZE-1] of byte; (* type of user key *)
   tbuf=array[0..bufsize-1] of byte;

const
   MODE_ECB    =         1;    (*  Are we ciphering in ECB mode?   *)
   MODE_CBC    =         2;    (*  Are we ciphering in CBC mode?   *)
   MODE_CFB1   =         3;    (*  Are we ciphering in 1-bit CFB mode? *)

type
   tMaxInternalKey=array[0..maxInternalKeySize-1] of byte;
   tMaxBuffer=array[0..MAX_BLOCK_SIZE-1] of byte;
   keyInstance =
      record
         direction:byte;         (* encryption or decryption *)
         keyLen:byte;            (* length of key in bytes *)
         keyMaterial:tBinaryKey; (* original user key *)
         internalKey:tMaxInternalKey;
         blockSize:byte;         (* in bytes *)
      end;

   cipherInstance=
      record
         mode: byte;     (* MODE_ECB, MODE_CBC, or MODE_CFB1 *)
         IV: tMaxBuffer; (* Initialization Vector *)
      end;


function MergeBytes(hibyte : byte; lobyte : byte) : longint;
procedure EncryptBuf(var cipher : cipherInstance; var key : keyInstance; var buf, cbuf : tbuf);
procedure DecryptBuf(var cipher : cipherInstance; var key : keyInstance; var cbuf, buf : tbuf);
procedure cipherInit(var cipher:cipherInstance; mode:byte; var IV; blockSize:byte);
procedure makeKey(var key:keyInstance; direction:byte; keyLen:byte; keyMaterial:tBinaryKey; blockSize:byte);
procedure blockEncrypt(var cipher:cipherInstance; var key:keyInstance; var inpBuffer; inputLen:byte; var outBuffer);
procedure blockDecrypt(var cipher:cipherInstance; var key:keyInstance; var inpBuffer; inputLen:byte; var outBuffer);


implementation

procedure makePermutation(var permutation;lastElem:byte);
(* receives an arbitrary byte array of (lastElem+1) elements and
   returns a permutation with values between 0 and lastElem *)
var
   permu:array[0..255] of byte absolute permutation;
   use:array[0..255] of byte;
   i,j,last:word;
begin
   for i:=0 to lastElem do use[i]:=i;
   last:=lastElem;
   j:=0;
   for i:=0 to lastElem-1 do
   begin
      j:=(j+permu[i]) mod (last+1);
      permu[i]:=use[j];
      if j<last then move(use[j+1],use[j],last-j);
      dec(last);
      if j>last then j:=0;
   end;
   permu[lastElem]:=use[0];
end;

procedure invertPermutation(var permutation;lastElem:byte);
(* receives a permutation with (lastElem+1) values and inverts it *)
var orig:array[0..255] of byte absolute permutation;
   invert:array[0..255] of byte;
   i:byte;
begin
   for i:=0 to lastElem do invert[ orig[i] ]:=i;
   move(invert,orig,lastElem+1);
end;

procedure makeInternalKey(direction:byte;var internalKey;blockSize:word);
(* receives an internalKey with arbitrary values and returns a well
   structured, valid internal key *)
var
   internKey:tBuffer absolute internalKey;
   used:array[0..MAX_BLOCK_SIZE-1] of boolean;
   ite,j,i,k,l:byte;
   ikPosi:word;
   bombPermu:^tBuffer;
begin ikPosi:=0;
   for ite:=0 to numIter-1 do
   begin inc(ikPosi,blockSize);
      makePermutation(internKey[ikPosi],255);
      if direction=DIR_DECRYPT then invertPermutation(internKey[ikPosi],255);
      inc(ikPosi,256);
      bombPermu:=addr(internKey[ikPosi]);
      makePermutation(bombPermu^,blockSize-1);

      (* now make certain that bombPermu has a maximum cycle of BLOCK_SIZE *)
      fillchar(used,blockSize,false);
      j:=0;
      for i:=0 to blockSize-2 do
      begin
         if BombPermu^[j]=0 then (* smaller cycle detected *)
         begin k:=j;
            repeat k:=(k+1) mod blockSize until not used[k];
            BombPermu^[j]:=k;
            l:=k;
            while BombPermu^[l]<>k do l:=BombPermu^[l];
            BombPermu^[l]:=0;
         end;
         used[j]:=true;
         j:=BombPermu^[j];
      end;

      (* now make certain that Bomb permutation never points to next element *)
      for i:=0 to blockSize-1 do
         if BombPermu^[i]=(i+1) mod blockSize then
            bombPermu^[i]:=(i+2) mod blockSize;

      inc(ikPosi,blockSize);
   end;
end;

procedure encryptFrog(var plainText;var internalKey;var cipherText;blockSize:byte);
(* uses internalKey to encrypt plainText of blockSize bytes and leaves
   result in cipherText; plainText and cipherText can point to the same
   position *)
var
   cipherTe:tBuffer absolute cipherText;
   internKey:tBuffer absolute internalKey;
   ite,ib:byte;
   xorBu,substPermu,bombPermu:^tBuffer;
   ikPosi:word;
begin
   move(plainText,cipherTe,blockSize);
   ikPosi:=0;
   for ite:=0 to numIter-1 do
   begin
      xorBu:=addr(internKey[ikPosi]);      inc(ikPosi,blockSize);
      substPermu:=addr(internKey[ikPosi]); inc(ikPosi,256);
      bombPermu:=addr(internKey[ikPosi]);  inc(ikPosi,blockSize);
      for ib:=0 to blockSize-1 do
      begin
         cipherTe[ib]:=cipherTe[ib] xor xorBu^[ib];
         cipherTe[ib]:=SubstPermu^[cipherTe[ib]];
         if ib<blockSize-1
            then cipherTe[ib+1]:=cipherTe[ib+1] xor cipherTe[ib]
            else cipherTe[0]:=cipherTe[0] xor cipherTe[ib];
         cipherTe[BombPermu^[ib]]:=
            cipherTe[BombPermu^[ib]] xor cipherTe[ib];
      end;
   end;
end;

procedure decryptFrog(var cipherText;var internalKey;var plainText;blockSize:byte);
(* uses internalKey to decrypt cipherText of blockSize bytes and leaves
   result in plainText; cipherText and plainText can point to the same
   position *)
var
   plainTe:tBuffer absolute plainText;
   internKey:tBuffer absolute internalKey;
   ite,ib:byte;
   xorBu,substPermu,bombPermu:^tBuffer;
   ikPosi:word;
begin
   move(cipherText,plainTe,blockSize);
   ikPosi:=8*(2*blockSize+256); (* size of internal key *)
   for ite:=numIter-1 downto 0 do
   begin
      dec(ikPosi,blockSize); bombPermu:=addr(internKey[ikPosi]);
      dec(ikPosi,256);       substPermu:=addr(internKey[ikPosi]);
      dec(ikPosi,blockSize); xorBu:=addr(internKey[ikPosi]);
      for ib:=blockSize-1 downto 0 do
      begin
         plainTe[BombPermu^[ib]]:=
            plainTe[BombPermu^[ib]] xor plainTe[ib];
         if ib<blockSize-1
            then plainTe[ib+1]:=plainTe[ib+1] xor plainTe[ib]
            else plainTe[0]:=plainTe[0] xor plainTe[blockSize-1];
         plainTe[ib]:=SubstPermu^[plainTe[ib]];
         plainTe[ib]:=plainTe[ib] xor xorBu^[ib];
      end;
   end;
end;

procedure hashKey(var binaryKey:tBinaryKey;keyLen:byte;var randomKey;blockSize:byte);
(* uses binaryKey to fill randomKey with values that have good random
   statistical properties *)
const
(* The values of randomSeed were computed as the modulo 256 of the
   first 251 groups of random digits in the RAND tables. This initialization
   of randomSeed can be substituted by other values, to produce non standard
   versions of FROG that are as strong as the standard version *)
   randomSeed:array[0..250] of byte=(
      113, 21,232, 18,113, 92, 63,157,124,193,166,197,126, 56,229,229,
      156,162, 54, 17,230, 89,189, 87,169,  0, 81,204,  8, 70,203,225,
      160, 59,167,189,100,157, 84, 11,  7,130, 29, 51, 32, 45,135,237,
      139, 33, 17,221, 24, 50, 89, 74, 21,205,191,242, 84, 53,  3,230,
      231,118, 15, 15,107,  4, 21, 34,  3,156, 57, 66, 93,255,191,  3,
       85,135,205,200,185,204, 52, 37, 35, 24, 68,185,201, 10,224,234,
        7,120,201,115,216,103, 57,255, 93,110, 42,249, 68, 14, 29, 55,
      128, 84, 37,152,221,137, 39, 11,252, 50,144, 35,178,190, 43,162,
      103,249,109,  8,235, 33,158,111,252,205,169, 54, 10, 20,221,201,
      178,224, 89,184,182, 65,201, 10, 60,  6,191,174, 79, 98, 26,160,
      252, 51, 63, 79,  6,102,123,173, 49,  3,110,233, 90,158,228,210,
      209,237, 30, 95, 28,179,204,220, 72,163, 77,166,192, 98,165, 25,
      145,162, 91,212, 41,230,110,  6,107,187,127, 38, 82, 98, 30, 67,
      225, 80,208,134, 60,250,153, 87,148, 60, 66,165, 72, 29,165, 82,
      211,207,  0,177,206, 13,  6, 14, 92,248, 60,201,132, 95, 35,215,
      118,177,121,180, 27, 83,131, 26, 39, 46, 12);

var buffer:array[0..MAX_BLOCK_SIZE-1] of byte;
   simpleKey:array[0..maxinternalKeySize-1] of byte;
   randKey:tBuffer absolute randomKey;
   last,iSeed,iKey,keyLen1:byte;
   i,size,internalKeySize:word;
begin
   internalKeySize:=8*(2*blockSize+256);

   (* build initial internalKey *)
   iSeed:=0;iKey:=0;keyLen1:=keyLen-1;
   for i:=0 to internalKeySize-1 do
   begin
      SimpleKey[i]:=randomSeed[iSeed] xor binaryKey[iKey];
      if iSeed<250 then inc(iSeed) else iSeed:=0;
      if iKey<keyLen1 then inc(iKey) else iKey:=0;
   end;
   makeInternalKey(DIR_ENCRYPT,simpleKey,blockSize);

   (* build plaintext buffer *)
   fillchar(buffer,blockSize,0);
   last:=keyLen1;
   if last>=blockSize then last:=blockSize-1;
   for i:=0 to last do buffer[i]:=buffer[i] xor binaryKey[i];
   buffer[0]:=buffer[0] xor keyLen;

   (* produce hashed randomKey using CBC encryptions *)
   i:=0;
   repeat
      encryptFrog(buffer,simpleKey,buffer,blockSize);
      size:=internalKeySize-i;
      if size>blockSize then size:=blockSize;
      move(buffer,randKey[i],size);
      inc(i,size);
   until i=internalKeySize;
end;

(* ------------------------ part B: NIST API -------------------------*)

(* for legibility no error messages are included *)

procedure makeKey(var key:keyInstance; direction:byte; keyLen:byte;
                      keyMaterial:tBinaryKey; blockSize:byte);
(* Computes internal key.
   Inputs:
      Cipher direction (DIR_ENCRYPT or DIR_DECRYPT).
      KeyMaterial, a binary array that holds the user's key.
      KeyLen, the binary key's length in bytes. (For example for a 128
          bit long key, keyLen = 16.) Legal values: 5..125
      BlockSize, the size of the blocks to be encrypted or decrypted.
          Legal values: 8..128.
   Returns:
      key instance that holds the internal key.

   When decrypting in CFB1 mode, makeKey must be called with
   direction set to DIR_ENCRYPT!  *)
begin
   key.direction:=   direction;
   key.keyLen:=      keyLen;
   key.keyMaterial:= keyMaterial;

   hashKey(keyMaterial,keyLen,key.internalKey,blockSize);
   makeInternalKey(direction,key.internalKey,blockSize);
end;

procedure cipherInit(var cipher:cipherInstance; mode:byte; var IV; blockSize:byte);
(* initializes the cipher instance *)
begin
   cipher.mode:=mode;
   move(IV,cipher.IV,blockSize);
end;

procedure shift1bitLeft(var buffer; blockSize:word);
(* moves an entire block of BLOCK_SIZE bytes 1 bit to the left,
   i.e. towards the most significant position *)
var i:byte;
   buf:tBuffer absolute buffer;
begin
   for i:=blockSize-1 downto 0 do
   begin
      buf[i]:=buf[i] shl 1;
      if i>0 then buf[i]:=buf[i] or (buf[i-1] shr 7);
   end;
end;

procedure blockEncrypt(var cipher:cipherInstance; var key:keyInstance;
                       var inpBuffer; inputLen:byte; var outBuffer);
(* Receives the cipher instance, the key instance, the input plaintext,
   its length in bytes. Encrypts the plaintext in ECB, CBC or CFB 1 bit
   mode and returns the ciphertext in outBuffer *)
var i:byte;
   inpBuf:tBuffer absolute inpBuffer;
   outBuf:tBuffer absolute outBuffer;
begin with cipher,key do begin
   blockSize:=inputLen;

   case mode of
      MODE_ECB: encryptFrog(inpBuf,internalKey,outBuf,blockSize);
      MODE_CBC:
         begin
            for i:=0 to blockSize-1 do
               outBuf[i]:=inpBuf[i] xor IV[i];
            encryptFrog(outBuf,internalKey,outBuf,blockSize);
            move(outBuf,IV,blockSize);
         end;
      MODE_CFB1:
         (* Receives plaintext bit in most significant position of input and
            returns ciphertext bit in most significant position of outBuffer *)
         begin
            encryptFrog(IV,internalKey,IV,blockSize);
            outBuf[blockSize-1]:=IV[blockSize-1] xor
                                     inpBuf[blockSize-1];
            shift1bitLeft(IV,blockSize);
            IV[0]:=IV[0] or (outBuf[blockSize-1] shr 7);
         end;
   end;
end;end;

procedure blockDecrypt(var cipher:cipherInstance; var key:keyInstance;
                       var inpBuffer; inputLen:byte; var outBuffer);
(* Receives the cipher instance, the key instance, the input ciphertext,
   its length in bytes. Decrypts the ciphertext in ECB, CBC or CFB 1 bit
   mode and returns the plaintext in outBuffer *)
var i:byte;
   inpBuf:tBuffer absolute inpBuffer;
   outBuf:tBuffer absolute outBuffer;
begin with cipher,key do begin
   blockSize:=inputLen;

   case mode of
      MODE_ECB: decryptFrog(inpBuf,internalKey,outBuf,blockSize);
      MODE_CBC:
         begin
            decryptFrog(inpBuf,internalKey,outBuf,blockSize);
            for i:=0 to blockSize-1 do
               outBuf[i]:=outBuf[i] xor IV[i];
            move(inpBuf,IV,blockSize);
         end;
      MODE_CFB1:
         (* Receives cipher bit in most significant position of input and
            returns plaintext bit in most significant position of outBuffer.
            When decrypting in CFB1 mode, makeKey must be called with
            direction set to DIR_ENCRYPT! *)
         begin
            encryptFrog(IV,internalKey,IV,blockSize);
            outBuf[blockSize-1]:=IV[blockSize-1] xor
                                     inpBuf[blockSize-1];
            shift1bitLeft(IV,blockSize);
            IV[0]:=IV[0] or (inpBuf[blockSize-1] shr 7);
         end;
   end;
end;end;

(* Functions for Krypto to encrypt/decrypt files *)

function MergeBytes(hibyte : byte; lobyte : byte) : longint;
var tmp : longint;
begin
        tmp:=hibyte;
        tmp:=tmp shl 8;
        tmp:=tmp or lobyte;
        MergeBytes:=tmp;
end;

procedure EncryptBuf(var cipher : cipherInstance; var key : keyInstance; var buf, cbuf : tbuf);
var plain, crypted : tMaxBuffer;
    pos, pos2, i : longint;
begin
        pos := 0; pos2 := 0;
        while pos < sizeof(buf) do
        begin
                for i := 0 to blocksize-1 do
                begin
                        plain[i] := buf[pos];
                        inc(pos);
                end;
                blockEncrypt(cipher,key,plain,blockSize,crypted);
                for i:= 0 to blocksize-1 do
                begin
                        cbuf[pos2] := crypted[i];
                        inc(pos2)
                end;
        end;
end;

procedure DecryptBuf(var cipher : cipherInstance; var key : keyInstance; var cbuf, buf : tbuf);
var pos, pos2, i : longint;
    crypted, plain : tMaxBuffer;
begin
        pos := 0; pos2 := 0;
        while pos < sizeof(cbuf) do
        begin
                for i := 0 to blocksize - 1 do
                begin
                        crypted[i] := cbuf[pos];
                        inc(pos);
                end;
                blockDecrypt(cipher,key,crypted,blockSize,plain);
                for i := 0 to blocksize - 1 do
                begin
                        buf[pos2] := plain[i];
                        inc(pos2)
                end;
        end;
end;


begin
end.
