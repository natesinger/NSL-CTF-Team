from __future__ import absolute_import, division, print_function, unicode_literals

import ctypes
import numpy as np

from pi3d.constants import *
from pi3d.util import Log

if PIL_OK:
  from PIL import Image

def screenshot(filestring=None):
  """
  Save whatever's in the display to a file.

  Will save whatever has been rendered since the last call to Display.clear().

  The file will be saved in the same directory as the app if you don't add a path
  to it!
  
  If PIL is not available then the screenshot will be saved as a compressed 
  numpy array and '.npz' will be appended to the filestring you supply. 
  The image can be extracted from the npz file using:
    img = np.load('filestring.npz')['arr_0']
  
  If this function is called without any argument then it will not save to
  file and will return a numpy array of the screen. The array and file, if
  saved, will have the alpha values removed.
  """

  from pi3d.Display import Display

  w, h = Display.INSTANCE.width, Display.INSTANCE.height
  img = np.zeros((h, w, 4), dtype=np.uint8)
  opengles.glReadPixels(GLint(0), GLint(0), GLsizei(w), GLsizei(h), GL_RGBA, GL_UNSIGNED_BYTE, img.ctypes.data_as(ctypes.POINTER(GLubyte)))
  img = img[::-1,:,:3].copy()
  if filestring is None:
    return img

  if PIL_OK:
    im = Image.frombuffer('RGB', (w, h), img, 'raw', 'RGB', 0, 1)
    im.save(filestring, quality=90)
  else:
    np.savez_compressed('{}'.format(filestring), img)
