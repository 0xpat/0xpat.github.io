#!/usr/bin/env python

import pygtk
import gtk
import os
import sys
import random
import argparse

class PasteImg:
    
    # Removed 'ico' from list until can catch size error
    imgTypeSet = ['png', 'bmp', 'jpg', 'jpeg', 'tiff']

    def __init__(self):
        
        parser = argparse.ArgumentParser(description='PasteImg: Output clipboard to file')
        parser.add_argument('filename', nargs='?', default='',
                help='filename to use')
        parser.add_argument('-v','--version', action='version', version='%(prog)s 0.2')

        args = parser.parse_args()
        filename = args.filename
        
        clipb = gtk.clipboard_get()
        clipb.request_image(self.callback_img, filename)

    def callback_img(self, clipboard, pixbuf, filename):
        
        if filename == '':
            filename=''.join(random.choice('0123456789abcdef') for i in range(12))
            
         # Split filename suffix
        (shortname, extension) = os.path.splitext(filename)
        fileExt=extension.replace('.','')
        
        # Default to png
        imgType="png"

        if fileExt in self.imgTypeSet:
            # pixbuf only recongnises 'jpeg' as type
            if fileExt == 'jpg': fileExt = 'jpeg'
            imgType=fileExt
            
        elif fileExt == "":
            fileExt=imgType
            
        else:
            # Wrong extension
            print "Error: Unknown file extension '%s'" % extension
            sys.exit()

        # Save clipboard image to file
        if pixbuf is None:
            print 'No image available!'
        else:
            print 'Saving clipboard image to file(%s): %s.%s' % (imgType, shortname, fileExt)
            pixbuf.save(filename, imgType)
        
        self.exitPasteImg()
            
    def exitPasteImg(self):
        gtk.main_quit()

    def main(self):
        gtk.main()

if __name__ == "__main__":
    pimg = PasteImg()
    pimg.main()
