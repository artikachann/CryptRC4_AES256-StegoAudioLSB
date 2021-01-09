# We will use wave package available in native Python installation to read and write .wav audio file
import wave
# read wave audio file
song = wave.open("song.wav", mode='rb')
# Read frames and convert to byte array
frame_bytes = bytearray(list(song.readframes(song.getnframes())))

# read file text yang akan disisipkan
f = open(folder + "/" + filename_text, "r", encoding='utf-8')
string = f.readline()
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
# create file audio
    result_filename = filename_audio.split(".")[0] + "_result" + etc + ".wav"
    with wave.open(folder + "/" + result_filename, "wb") as fd:
    fd.setparams(song.getparams())
    fd.writeframes(frame_modified)
song.close()
return result_filename