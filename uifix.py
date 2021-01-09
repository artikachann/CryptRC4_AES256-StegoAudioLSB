import tkinter as tk
from tkinter import Tk, Button, Label, Menu, Entry, INSERT, Frame, filedialog
from tkinter import messagebox
from tkinter import filedialog
from tkinter.filedialog import askopenfilename
import binascii
import codecs
import os
import time
from time import time
from humanfriendly import format_timespan
import hashlib
from filehash import FileHash
from ast import literal_eval
import rc4
from rc4 import encrypt
from rc4 import decrypt
import aes256
from aes256 import encrypt
from aes256 import decrypt
import wave

LARGE_FONT= ("Kufam", 12) 

class CryptoProgram(tk.Tk):
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs) 
        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand = True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)
        self.frames = {}
        for F in (MainMenu, EncryptRC4, EncryptAES, HideLSB, Verification, ExtractLSB, DecryptAES, DecryptRC4):
            frame = F(container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        self.show_frame(MainMenu)
    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()

class MainMenu(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self,parent, bg="#f1f1f1")
        mainMenuTitleText = tk.Label(self, text="Cryptography & Steganography", font=LARGE_FONT, bg="#f1f1f1", fg="#0a3d62")
        mainMenuTitleText.pack(pady=40,padx=10)
        encryptButton = tk.Button(self, text="Encrypt", bg="#0a3d62", fg="#ffffff", width=20, height=1,
                            command=lambda: controller.show_frame(EncryptRC4))
        encryptButton.pack(pady=5, padx=10)
        encryptButton.configure(relief=tk.FLAT)
        decryptButton = tk.Button(self, text="Decrypt", bg="#0a3d62", fg="#ffffff", width=20, height=1,
                            command=lambda: controller.show_frame(Verification))
        decryptButton.pack(pady=5, padx=10)
        decryptButton.configure(relief=tk.FLAT)

#all encrypt        
class EncryptRC4 (tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg="#f1f1f1")
        # title
        RC4EncryptTitleLabel = tk.Label(self, text="Encryption RC4", bg="#f1f1f1", fg="#0a3d62", font=LARGE_FONT)
        RC4EncryptTitleLabel.pack(pady=30,padx=30)
        # frame 1
        frame1 = Frame(self, bg="#f1f1f1")
        frame1.pack(fill='x')
        # label
        RC4EncryptTextLabel = tk.Label(frame1, text="Plaintext", bg="#f1f1f1", fg="#0a3d62", width=16)
        RC4EncryptTextLabel.pack(side='left', padx=10, pady=5)
        # entry message
        RC4EncryptPathFileText = tk.Entry(frame1, width=50, bg="#ffffff", fg="#0a3d62", relief=tk.FLAT)
        RC4EncryptPathFileText.pack(side='left', padx=14)
        # browse
        def openFile(): 
            global normal_message
            filename = filedialog.askopenfilename()
            if filename:
                with open(filename) as f:
                    normal_message = open(filename,'r')
                    normal_message = f.readline()
                    print("Normal Message : ", normal_message)
                    RC4EncryptPathFileText.insert(tk.END, "%s" % (filename))
        openFileButton = tk.Button(frame1, text="Browse", command=openFile, bg="#0a3d62", fg="#ffffff", relief=tk.FLAT)
        openFileButton.pack(fill='x', pady=5,padx=10)
        # frame 3
        frame3 = Frame(self, bg="#f1f1f1")
        frame3.pack(fill='x')
        # label
        RC4EncryptKeyLabel = tk.Label(frame3, text="Key", bg="#f1f1f1", fg="#0a3d62", width=16)
        RC4EncryptKeyLabel.pack(side='left', pady=5,padx=10)
        # entry key
        rc4_key = tk.StringVar()
        RC4EncryptKeyText = tk.Entry(frame3, textvariable=rc4_key, bg="#ffffff", fg="#0a3d62", relief=tk.FLAT)
        RC4EncryptKeyText.pack(fill='x', padx=14)
        # frame 4
        frame4 = Frame(self, bg="#f1f1f1")
        frame4.pack(fill='x')
        # function encrypt
        def encrypt_RC4():
            start_time = time()
            global ciphertext_rc4
            global ciphertext_rc4_in_str
            print("Normal Message : ", normal_message)
            msg = normal_message
            key = rc4_key.get()
            print("Key : ", key)
            ciphertext_rc4 = encrypt(msg, key)
            ciphertext_rc4_in_str = bytes.decode(ciphertext_rc4)
            print("Cipher Message : ", ciphertext_rc4_in_str)
            output_rc4.insert(tk.END, "%s" % (ciphertext_rc4_in_str))
            end_time = time()
            time_taken = end_time - start_time
            hours, rest = divmod(time_taken,3600)
            minutes, seconds = divmod(rest, 60)
            print("Time taken : ",  format_timespan(end_time - start_time))
            messagebox.showinfo("Success!", "Encrypt RC4 Success")
        # frame 5
        frame5 = Frame(self, bg="#f1f1f1")
        frame5.pack(fill='x')
        # button encrypt
        encryptRC4ExecuteButton = tk.Button(frame5, text="Encrypt RC4", bg="#0a3d62", fg="#ffffff", command=encrypt_RC4)
        encryptRC4ExecuteButton.pack(side='right', pady=5,padx=14)
        encryptRC4ExecuteButton.configure(relief=tk.FLAT)
        # frame 4
        frame4 = Frame(self, bg="#f1f1f1")
        frame4.pack(fill='x')
        # label
        RC4EncryptCipherLabel = tk.Label(frame4, text="Ciphertext RC4", bg="#f1f1f1", fg="#0a3d62", width=16)
        RC4EncryptCipherLabel.pack(side='left', pady=5,padx=10)
        # entry key
        output_rc4 = tk.Entry(frame4, bg="#ffffff", fg="#0a3d62", relief=tk.FLAT)
        output_rc4.pack(fill='x', padx=14)
        def writeFile():
            file = open('cipher-rc4_file.txt','a+')
            file.write(ciphertext_rc4_in_str)
            file.close()
        buttonWrite = Button(self, text = 'Write To File', bg="#0a3d62", fg="#f1f1f1", width=10, height=1, relief=tk.FLAT, command = writeFile)
        buttonWrite.pack(padx=14)
        # button back
        backButton = Button(self, text="Back", bg="#0a3d62", fg="#f1f1f1",
                    command=lambda: controller.show_frame(MainMenu))
        backButton.pack(side='left', padx=14, pady=5)
        backButton.configure(relief=tk.FLAT)
        # button next
        nextButton = Button(self, text="Next", bg="#0a3d62", fg="#f1f1f1",
                    command=lambda: controller.show_frame(EncryptAES))
        nextButton.pack(side='right', padx=14, pady=5)
        nextButton.configure(relief=tk.FLAT)

class EncryptAES (tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg="#f1f1f1")
        # title
        AESEncryptTitleLabel = tk.Label(self, text="Encryption AES", bg="#f1f1f1", fg="#0a3d62", font=LARGE_FONT)
        AESEncryptTitleLabel.pack(pady=30,padx=30)
        # frame 1
        frame1 = Frame(self, bg="#f1f1f1")
        frame1.pack(fill='x')
        # label
        AESEncryptTextLabel = tk.Label(frame1, text="Ciphertext RC4", bg="#f1f1f1", fg="#0a3d62", width=16)
        AESEncryptTextLabel.pack(side='left', padx=10, pady=5)
        # entry message
        AESEncryptPathFileText = tk.Entry(frame1, width=50, bg="#ffffff", fg="#0a3d62", relief=tk.FLAT)
        AESEncryptPathFileText.pack(side='left', padx=14)
        # browse
        def openFile(): 
            # global filename
            global cipher_rc4_msg
            filename = filedialog.askopenfilename()
            if filename:
                with open(filename) as f:
                    cipher_rc4_msg = open(filename,'r')
                    cipher_rc4_msg = f.readline()
                    print("Cipher Message : ", cipher_rc4_msg)
                    AESEncryptPathFileText.insert(tk.END, "%s" % (filename))
        openFileButton = tk.Button(frame1, text="Browse", command=openFile, bg="#0a3d62", fg="#ffffff", relief=tk.FLAT)
        openFileButton.pack(fill='x', pady=5,padx=10)
        # frame 3
        frame3 = Frame(self, bg="#f1f1f1")
        frame3.pack(fill='x')
        # label
        AESEncryptKeyLabel = tk.Label(frame3, text="Key", bg="#f1f1f1", fg="#0a3d62", width=16)
        AESEncryptKeyLabel.pack(side='left', pady=5,padx=10)
        # entry key
        aes_key = tk.StringVar()
        AESEncryptKeyText = tk.Entry(frame3, textvariable=aes_key, bg="#ffffff", fg="#0a3d62", relief=tk.FLAT)
        AESEncryptKeyText.pack(fill='x', padx=14)
        # frame 4
        frame4 = Frame(self, bg="#f1f1f1")
        frame4.pack(fill='x')
        # function encrypt
        def encrypt_AES():
            start_time = time()
            global ciphertext_aes
            global ciphertext_aes_in_str
            print("Cipher Message : ", cipher_rc4_msg)
            msg_aes = cipher_rc4_msg
            key = aes_key.get()
            print("Key : ", key)
            ciphertext_aes = encrypt(msg_aes, key)
            ciphertext_aes_in_str = bytes.decode(ciphertext_aes)
            print("Cipher Message : ", ciphertext_aes_in_str)
            output_aes.insert(tk.END, "%s" % (ciphertext_aes_in_str))
            end_time = time()
            time_taken = end_time - start_time
            hours, rest = divmod(time_taken,3600)
            minutes, seconds = divmod(rest, 60)
            print("Time taken : ",  format_timespan(end_time - start_time))
            messagebox.showinfo("Success!", "Encrypt AES Success")
        # frame 5
        frame5 = Frame(self, bg="#f1f1f1")
        frame5.pack(fill='x')
        # button encrypt
        encryptAESExecuteButton = tk.Button(frame5, text="Encrypt AES", bg="#0a3d62", fg="#ffffff", command=encrypt_AES)
        encryptAESExecuteButton.pack(side='right', pady=5,padx=14)
        encryptAESExecuteButton.configure(relief=tk.FLAT)
        # frame 4
        frame4 = Frame(self, bg="#f1f1f1")
        frame4.pack(fill='x')
        # label
        AESEncryptCipherLabel = tk.Label(frame4, text="Ciphertext AES", bg="#f1f1f1", fg="#0a3d62", width=16)
        AESEncryptCipherLabel.pack(side='left', pady=5,padx=10)
        # entry key
        output_aes = tk.Entry(frame4, bg="#ffffff", fg="#333333", relief=tk.FLAT)
        output_aes.pack(fill='x', padx=14)
        def writeFile():
            file = open('cipher-aes_file.txt','a+')
            file.write(ciphertext_aes_in_str)
            file.close()
        buttonWrite = Button(self, text = 'Write To File', bg="#0a3d62", fg="#f1f1f1", width=10, height=1, relief=tk.FLAT, command = writeFile)
        buttonWrite.pack(padx=14)
        # button back
        backButton = Button(self, text="Back", bg="#0a3d62", fg="#f1f1f1",
                    command=lambda: controller.show_frame(EncryptRC4))
        backButton.pack(side='left', padx=14, pady=5)
        backButton.configure(relief=tk.FLAT)
        # button next
        nextButton = Button(self, text="Next", bg="#0a3d62", fg="#f1f1f1",
                    command=lambda: controller.show_frame(HideLSB))
        nextButton.pack(side='right', padx=14, pady=5)
        nextButton.configure(relief=tk.FLAT)

class HideLSB (tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg="#f1f1f1")
        # title
        LSBEncodeTitleLabel = tk.Label(self, text="Hide Text to Audio", bg="#f1f1f1", fg="#0a3d62", font=LARGE_FONT)
        LSBEncodeTitleLabel.pack(pady=30,padx=30)
        # frame 1
        frame1 = Frame(self, bg="#f1f1f1")
        frame1.pack(fill='x')
        # label
        LSBEncodeTextLabel = tk.Label(frame1, text="Text", bg="#f1f1f1", fg="#0a3d62", width=16)
        LSBEncodeTextLabel.pack(side='left', padx=10, pady=5)
        # entry message
        LSBEncodePathFileText = tk.Entry(frame1, width=50, bg="#ffffff", fg="#0a3d62", relief=tk.FLAT)
        LSBEncodePathFileText.pack(side='left', padx=14)
        # browse
        def openFile(): 
            global text_input
            filename = filedialog.askopenfilename()
            if filename:
                with open(filename) as f:
                    text_input = open(filename,'r')
                    text_input = f.readline()
                    print("Cipher Message : ", text_input)
                    LSBEncodePathFileText.insert(tk.END, "%s" % (filename))
        openFileButton = tk.Button(frame1, text="Browse", command=openFile, bg="#0a3d62", fg="#ffffff", relief=tk.FLAT)
        openFileButton.pack(fill='x', pady=5,padx=10)
        frame2 = Frame(self, bg="#f1f1f1")
        frame2.pack(fill='x')
        # label
        AudioTextLabel = tk.Label(frame2, text="Audio", bg="#f1f1f1", fg="#0a3d62", width=16)
        AudioTextLabel.pack(side='left', padx=10, pady=5)
        # entry message
        PathFileText = tk.Entry(frame2, width=50, bg="#ffffff", fg="#0a3d62", relief=tk.FLAT)
        PathFileText.pack(side='left', padx=14)
        def openFileAudio(): 
            # read wave audio file
            global song
            filename = filedialog.askopenfilename()
            if filename:
                with open(filename) as f:
                    song = wave.open(filename, mode='rb')
                    # text_input = f.readline()
                    PathFileText.insert(tk.END, "%s" % (filename))
        openFileButton = tk.Button(frame2, text="Browse", command=openFileAudio, bg="#0a3d62", fg="#ffffff", relief=tk.FLAT)
        openFileButton.pack(fill='x', pady=5,padx=10)
        # frame 4
        frame4 = Frame(self, bg="#f1f1f1")
        frame4.pack(fill='x')
        # function encode
        def texttoaudio():
            start_time = time()
            # Read frames and convert to byte array
            frame_bytes = bytearray(list(song.readframes(song.getnframes())))
            # text message
            string=text_input
            # Append dummy data to fill out rest of the bytes. Receiver shall detect and remove these characters.
            string = string + int((len(frame_bytes)-(len(string)*8*8))/8) *'#'
            # Convert text to bit array
            bits = list(map(int, ''.join([bin(ord(i)).lstrip('0b').rjust(8,'0') for i in string])))
            # Replace LSB of each byte of the audio data by one bit from the text bit array
            for i, bit in enumerate(bits):
                frame_bytes[i] = (frame_bytes[i] & 254) | bit
            # Get the modified bytes
            frame_modified = bytes(frame_bytes)
            # Write bytes to a new wave audio file
            with wave.open('song_embedded.wav', 'wb') as fd:
                fd.setparams(song.getparams())
                fd.writeframes(frame_modified)
            song.close()
            end_time = time()
            time_taken = end_time - start_time
            hours, rest = divmod(time_taken,3600)
            minutes, seconds = divmod(rest, 60)
            print("Time taken : ",  format_timespan(end_time - start_time))
            messagebox.showinfo("Success!", "Hide Text in Audio Success")
        # frame 5
        frame5 = Frame(self, bg="#f1f1f1")
        frame5.pack(fill='x')
        # button encode
        encodeLSBExecuteButton = tk.Button(frame5, text="Hide", bg="#0a3d62", fg="#ffffff", command=texttoaudio)
        encodeLSBExecuteButton.pack(side='right', pady=5,padx=14)
        encodeLSBExecuteButton.configure(relief=tk.FLAT)
        def getHashAudio(): 
            global fileHash
            md5hasher = FileHash('md5')
            md5hasher.hash_file('song_embedded.wav')
            fileHash = md5hasher.hash_file('song_embedded.wav')
            filehash_audio = open('hash-audio-password.txt', 'a+')
            filehash_audio.write(fileHash)
            filehash_audio.close()
            print("FileHash : ", fileHash)
            messagebox.showinfo("File Hash", fileHash)
        loadFileButton = tk.Button(self, text="Get Hash Audio", command=getHashAudio, bg="#0a3d62", fg="#ffffff", width=12, height=1, relief=tk.FLAT)
        loadFileButton.pack(padx=14)
        # button back
        backButton = Button(self, text="Back", bg="#0a3d62", fg="#f1f1f1",
                    command=lambda: controller.show_frame(EncryptAES))
        backButton.pack(side='left', padx=14, pady=5)
        backButton.configure(relief=tk.FLAT)
        # button next
        nextButton = Button(self, text="Next", bg="#0a3d62", fg="#f1f1f1",
                    command=lambda: controller.show_frame(MainMenu))
        nextButton.pack(side='right', padx=14, pady=5)
        nextButton.configure(relief=tk.FLAT)      

class Verification (tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg="#f1f1f1")
        # title
        verifyTitleLabel = tk.Label(self, text="Verify Audio File", bg="#f1f1f1", fg="#0a3d62", font=LARGE_FONT)
        verifyTitleLabel.pack(pady=30,padx=30)
        # frame audio
        frameEntryAudio = Frame(self, bg="#f1f1f1")
        frameEntryAudio.pack(fill='x')
        # label
        verifyTextLabel = tk.Label(frameEntryAudio, text="Audio", bg="#f1f1f1", fg="#0a3d62", width=20)
        verifyTextLabel.pack(side='left', pady=5,padx=10)
        # entry stego audio
        load_audio_path= tk.Entry(frameEntryAudio, width=50, bg="#ffffff", fg="#0a3d62", relief=tk.FLAT)
        load_audio_path.pack(side='left', padx=14)
        def browseAudio():
            global fileAudio
            global filename_audio
            filename_audio = filedialog.askopenfilename()
            dir_path = os.path.split(filename_audio)[0]
            global audioFileHash
            audioFileHash = FileHash('md5')
            audioFileHash.hash_file(filename_audio)
            audioFileHash = audioFileHash.hash_file(filename_audio)
            print("FileHash : ", audioFileHash)
            load_audio_path.insert(tk.END, filename_audio)
        # button browse
        openFileButton = tk.Button(frameEntryAudio, text="Browse", bg="#0a3d62", fg="#ffffff", relief=tk.FLAT, command=browseAudio)
        openFileButton.pack(fill='x', pady=5,padx=14)
        # frame hash
        frameEntryHash = Frame(self, bg="#f1f1f1")
        frameEntryHash.pack(fill='x')
        # label
        hashAudioLabel = tk.Label(frameEntryHash, text="File Hash", bg="#f1f1f1", fg="#0a3d62", width=20)
        hashAudioLabel.pack(side='left', pady=5,padx=10)
        # entry hash
        hashAudioInput = tk.StringVar()
        audioHashText = tk.Entry(frameEntryHash, width=70, textvariable=hashAudioInput, bg="#ffffff", fg="#0a3d62", relief=tk.FLAT)
        audioHashText.pack(fill='x', padx=14)
        def verifyHash():
            hashAudio = hashAudioInput.get()
            print("FileHash : ", hashAudio)
            if ((audioFileHash == hashAudio)): 
                messagebox.showinfo("Verification", "File Hash is correct")
                print("File Hash is correct") 
            else: 
                messagebox.showinfo("Verification", "Incorrect File Hash")
                print("Incorrect File Hash") 
        # frame button verify
        frameButtonVerify = Frame(self, bg="#f1f1f1")
        frameButtonVerify.pack(fill='x')
        # button verify
        printHashButton = tk.Button(frameButtonVerify, text="Verification", command=verifyHash, bg="#0a3d62", fg="#ffffff", relief=tk.FLAT)
        printHashButton.pack(side='right', padx=14, pady=5)
        # button back
        backButton = Button(self, text="Back", bg="#0a3d62", fg="#f1f1f1",
                    command=lambda: controller.show_frame(MainMenu))
        backButton.pack(side='left', padx=14, pady=5)
        backButton.configure(relief=tk.FLAT)
        # button next
        nextButton = Button(self, text="Next", bg="#0a3d62", fg="#ffffff", relief=tk.FLAT,
                    command=lambda: controller.show_frame(ExtractLSB))
        nextButton.pack(side='right', padx=14, pady=5)      

#all decrypt
class ExtractLSB (tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg="#f1f1f1")
        # title
        LSBDecryptTitleLabel = tk.Label(self, text="Extract Audio To Text", bg="#f1f1f1", fg="#0a3d62", font=LARGE_FONT)
        LSBDecryptTitleLabel.pack(pady=30,padx=30)
        frame2 = Frame(self, bg="#f1f1f1")
        frame2.pack(fill='x')
        # label
        AudioTextLabel = tk.Label(frame2, text="Audio", bg="#f1f1f1", fg="#0a3d62", width=16)
        AudioTextLabel.pack(side='left', padx=10, pady=5)
        # entry message
        PathFileText = tk.Entry(frame2, width=50, bg="#ffffff", fg="#0a3d62", relief=tk.FLAT)
        PathFileText.pack(side='left', padx=14)
        def openFileAudioExtract(): 
            # read wave audio file
            global song
            filename = filedialog.askopenfilename()
            if filename:
                with open(filename) as f:
                    song = wave.open(filename, mode='rb')
                    # text_input = f.readline()
                    PathFileText.insert(tk.END, "%s" % (filename))
        openFileButton = tk.Button(frame2, text="Browse", command=openFileAudioExtract, bg="#0a3d62", fg="#ffffff", relief=tk.FLAT)
        openFileButton.pack(fill='x', pady=5,padx=10)
        # frame 4
        frame4 = Frame(self, bg="#f1f1f1")
        frame4.pack(fill='x')
        # function decode
        def audiototext():
            start_time = time()
            global decoded
            # Convert audio to byte array
            frame_bytes = bytearray(list(song.readframes(song.getnframes())))
            # Extract the LSB of each byte
            extracted = [frame_bytes[i] & 1 for i in range(len(frame_bytes))]
            # Convert byte array back to string
            string = "".join(chr(int("".join(map(str,extracted[i:i+8])),2)) for i in range(0,len(extracted),8))
            # Cut off at the filler characters
            decoded = string.split("###")[0]
            # Print the extracted text
            print("Sucessfully decoded: "+decoded)
            song.close()
            end_time = time()
            time_taken = end_time - start_time
            hours, rest = divmod(time_taken,3600)
            minutes, seconds = divmod(rest, 60)
            print("Time taken : ",  format_timespan(end_time - start_time))
            messagebox.showinfo("Success!", "Extract Audio To Text Success")
        # frame 5
        frame5 = Frame(self, bg="#f1f1f1")
        frame5.pack(fill='x')
        # button decode
        decodeLSBExecuteButton = tk.Button(frame5, text="Extract", bg="#0a3d62", fg="#ffffff", command=audiototext)
        decodeLSBExecuteButton.pack(side='right', pady=5,padx=14)
        decodeLSBExecuteButton.configure(relief=tk.FLAT)
        def writeFile():
            file = open('extract-msg.txt','a+')
            file.write(decoded)
            file.close()
        buttonWrite = Button(self, text = 'Write To File', bg="#0a3d62", fg="#f1f1f1", width=10, height=1, relief=tk.FLAT, command = writeFile)
        buttonWrite.pack(padx=14)
        # button back
        backButton = Button(self, text="Back", bg="#0a3d62", fg="#f1f1f1",
                    command=lambda: controller.show_frame(Verification))
        backButton.pack(side='left', padx=14, pady=5)
        backButton.configure(relief=tk.FLAT)
        # button next
        nextButton = Button(self, text="Next", bg="#0a3d62", fg="#f1f1f1",
                    command=lambda: controller.show_frame(DecryptAES))
        nextButton.pack(side='right', padx=14, pady=5)
        nextButton.configure(relief=tk.FLAT)

class DecryptAES (tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg="#f1f1f1")
        # title
        AESDecryptTitleLabel = tk.Label(self, text="Decryption AES", bg="#f1f1f1", fg="#0a3d62", font=LARGE_FONT)
        AESDecryptTitleLabel.pack(pady=30,padx=30)
        # frame 1
        frame1 = Frame(self, bg="#f1f1f1")
        frame1.pack(fill='x')
        # label
        AESDecryptTextLabel = tk.Label(frame1, text="Ciphertext AES", bg="#f1f1f1", fg="#0a3d62", width=16)
        AESDecryptTextLabel.pack(side='left', padx=10, pady=5)
        # entry message
        AESDecryptPathFileText = tk.Entry(frame1, width=50, bg="#ffffff", fg="#0a3d62", relief=tk.FLAT)
        AESDecryptPathFileText.pack(side='left', padx=14)
        # browse
        def openFile(): 
            global cipher_aes_message
            filename = filedialog.askopenfilename()
            if filename:
                with open(filename) as f:
                    cipher_aes_message = open(filename,'r')
                    cipher_aes_message = f.readline()
                    print("Cipher Message : ", cipher_aes_message)
                    AESDecryptPathFileText.insert(tk.END, "%s" % (filename))
        openFileButton = tk.Button(frame1, text="Browse", command=openFile, bg="#0a3d62", fg="#ffffff", relief=tk.FLAT)
        openFileButton.pack(fill='x', pady=5,padx=10)
        # frame 3
        frame3 = Frame(self, bg="#f1f1f1")
        frame3.pack(fill='x')
        # label
        AESDecryptKeyLabel = tk.Label(frame3, text="Key", bg="#f1f1f1", fg="#0a3d62", width=16)
        AESDecryptKeyLabel.pack(side='left', pady=5,padx=10)
        # entry key
        aes_key = tk.StringVar()
        AESDecryptKeyText = tk.Entry(frame3, textvariable=aes_key, bg="#ffffff", fg="#0a3d62", relief=tk.FLAT)
        AESDecryptKeyText.pack(fill='x', padx=14)
        # frame 4
        frame4 = Frame(self, bg="#f1f1f1")
        frame4.pack(fill='x')
        # function decrypt
        def decrypt_AES():
            start_time = time()
            global decrypttext_aes
            global decrypttext_aes_in_str
            print("Cipher Message : ", cipher_aes_message)
            cipher_aes = cipher_aes_message
            key = aes_key.get()
            print("Key : ", key)
            decrypttext_aes = decrypt(cipher_aes, key)
            decrypttext_aes_in_str = bytes.decode(decrypttext_aes)
            print("Cipher Message : ", decrypttext_aes_in_str)
            output_aes.insert(tk.END, "%s" % (decrypttext_aes_in_str))
            end_time = time()
            time_taken = end_time - start_time
            hours, rest = divmod(time_taken,3600)
            minutes, seconds = divmod(rest, 60)
            print("Time taken : ",  format_timespan(end_time - start_time))
            messagebox.showinfo("Success!", "Decrypt AES Success")
        # frame 5
        frame5 = Frame(self, bg="#f1f1f1")
        frame5.pack(fill='x')
        # button decrypt
        decryptAESExecuteButton = tk.Button(frame5, text="Decrypt AES", bg="#0a3d62", fg="#ffffff", command=decrypt_AES)
        decryptAESExecuteButton.pack(side='right', pady=5,padx=14)
        decryptAESExecuteButton.configure(relief=tk.FLAT)
        # frame 4
        frame4 = Frame(self, bg="#f1f1f1")
        frame4.pack(fill='x')
        # label
        AESDecryptCipherLabel = tk.Label(frame4, text="Ciphertext RC4", bg="#f1f1f1", fg="#0a3d62", width=16)
        AESDecryptCipherLabel.pack(side='left', pady=5,padx=10)
        # entry key
        output_aes = tk.Entry(frame4, bg="#ffffff", fg="#0a3d62", relief=tk.FLAT)
        output_aes.pack(fill='x', padx=14)
        def writeFile():
            file = open('decrypt-aes_file.txt','a+')
            file.write(decrypttext_aes_in_str)
            file.close()
        buttonWrite = Button(self, text = 'Write To File', bg="#0a3d62", fg="#f1f1f1", width=10, height=1, relief=tk.FLAT, command = writeFile)
        buttonWrite.pack(padx=14)
        # button back
        backButton = Button(self, text="Back", bg="#0a3d62", fg="#f1f1f1",
                    command=lambda: controller.show_frame(ExtractLSB))
        backButton.pack(side='left', padx=14, pady=5)
        backButton.configure(relief=tk.FLAT)
        # button next
        nextButton = Button(self, text="Next", bg="#0a3d62", fg="#f1f1f1",
                    command=lambda: controller.show_frame(DecryptRC4))
        nextButton.pack(side='right', padx=14, pady=5)
        nextButton.configure(relief=tk.FLAT)

class DecryptRC4 (tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent, bg="#f1f1f1")
        # title
        RC4DecryptTitleLabel = tk.Label(self, text="Decryption RC4", bg="#f1f1f1", fg="#0a3d62", font=LARGE_FONT)
        RC4DecryptTitleLabel.pack(pady=30,padx=30)
        # frame 1
        frame1 = Frame(self, bg="#f1f1f1")
        frame1.pack(fill='x')
        # label
        RC4DecryptTextLabel = tk.Label(frame1, text="Ciphertext RC4", bg="#f1f1f1", fg="#0a3d62", width=16)
        RC4DecryptTextLabel.pack(side='left', padx=10, pady=5)
        # entry message
        RC4DecryptPathFileText = tk.Entry(frame1, width=50, bg="#ffffff", fg="#0a3d62", relief=tk.FLAT)
        RC4DecryptPathFileText.pack(side='left', padx=14)
        # browse
        def openFile(): 
            global cipher_rc4_message
            filename = filedialog.askopenfilename()
            if filename:
                with open(filename) as f:
                    cipher_rc4_message = open(filename,'r')
                    cipher_rc4_message = f.readline()
                    print("Cipher Message : ", cipher_aes_message)
                    RC4DecryptPathFileText.insert(tk.END, "%s" % (filename))
        openFileButton = tk.Button(frame1, text="Browse", command=openFile, bg="#0a3d62", fg="#ffffff", relief=tk.FLAT)
        openFileButton.pack(fill='x', pady=5,padx=10)
        # frame 3
        frame3 = Frame(self, bg="#f1f1f1")
        frame3.pack(fill='x')
        # label
        RC4DecryptKeyLabel = tk.Label(frame3, text="Key", bg="#f1f1f1", fg="#0a3d62", width=16)
        RC4DecryptKeyLabel.pack(side='left', pady=5,padx=10)
        # entry key
        rc4_key = tk.StringVar()
        RC4DecryptKeyText = tk.Entry(frame3, textvariable=rc4_key, bg="#ffffff", fg="#0a3d62", relief=tk.FLAT)
        RC4DecryptKeyText.pack(fill='x', padx=14)
        # frame 4
        frame4 = Frame(self, bg="#f1f1f1")
        frame4.pack(fill='x')
        # function decrypt
        def decrypt_RC4():
            start_time = time()
            global decrypttext_rc4_in_str
            print("Cipher Message : ", cipher_rc4_message)
            plain_aes = cipher_rc4_message
            key = rc4_key.get()
            print("Key : ", key)
            decrypttext_rc4 = decrypt(plain_aes, key)
            decrypttext_rc4_in_str = bytes.decode(decrypttext_rc4)
            print("Normal Message : ", decrypttext_rc4_in_str)
            output_rc4.insert(tk.END, "%s" % (decrypttext_rc4_in_str))
            end_time = time()
            time_taken = end_time - start_time
            hours, rest = divmod(time_taken,3600)
            minutes, seconds = divmod(rest, 60)
            print("Time taken : ",  format_timespan(end_time - start_time))
            messagebox.showinfo("Success!", "Decrypt RC4 Success")
        # frame 5
        frame5 = Frame(self, bg="#f1f1f1")
        frame5.pack(fill='x')
        # button decrypt
        decryptRC4ExecuteButton = tk.Button(frame5, text="Decrypt RC4", bg="#0a3d62", fg="#ffffff", command=decrypt_RC4)
        decryptRC4ExecuteButton.pack(side='right', pady=5,padx=14)
        decryptRC4ExecuteButton.configure(relief=tk.FLAT)
        # frame 4
        frame4 = Frame(self, bg="#f1f1f1")
        frame4.pack(fill='x')
        # label
        RC4DecryptCipherLabel = tk.Label(frame4, text="Plaintext", bg="#f1f1f1", fg="#0a3d62", width=16)
        RC4DecryptCipherLabel.pack(side='left', pady=5,padx=10)
        # entry key
        output_rc4 = tk.Entry(frame4, bg="#ffffff", fg="#0a3d62", relief=tk.FLAT)
        output_rc4.pack(fill='x', padx=14)
        def writeFile():
            file = open('decrypt-rc4_file.txt','a+')
            file.write(decrypttext_rc4_in_str)
            file.close()
        buttonWrite = Button(self, text = 'Write To File', bg="#0a3d62", fg="#f1f1f1", width=10, height=1, relief=tk.FLAT, command = writeFile)
        buttonWrite.pack(padx=14)
        # button back
        backButton = Button(self, text="Back", bg="#0a3d62", fg="#f1f1f1",
                    command=lambda: controller.show_frame(DecryptAES))
        backButton.pack(side='left', padx=14, pady=5)
        backButton.configure(relief=tk.FLAT)
        # button next
        nextButton = Button(self, text="Next", bg="#0a3d62", fg="#f1f1f1",
                    command=lambda: controller.show_frame(MainMenu))
        nextButton.pack(side='right', padx=14, pady=5)
        nextButton.configure(relief=tk.FLAT)

app = CryptoProgram()
app.mainloop()