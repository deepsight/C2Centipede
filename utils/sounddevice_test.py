#!/usr/bin/env python3
"""Play a sine signal."""
import argparse
import sys

import numpy as np
import sounddevice as sd

start_idx = 0
frequency = 500.0
amplitude = 0.2

def beep(pluswhat):

    samplerate = sd.query_devices('default')['default_samplerate']

    def callback(outdata, frames, time, status):
        if status:
            print(status, file=sys.stderr)
        global start_idx
        t = (start_idx + np.arange(frames)) / samplerate
        t = t.reshape(-1, 1)
        outdata[:] = amplitude * np.sin(2 * np.pi * (frequency + pluswhat * 1.1) * t)
        start_idx += frames

    with sd.OutputStream(device="default", channels=1, callback=callback,
                         samplerate=samplerate):
        import time
        time.sleep(.1)


if __name__ == "__main__":
    beep(300)