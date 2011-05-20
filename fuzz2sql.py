#!/usr/bin/python

# Initial Release 0.1
# Authors: Brett Cunningham, Matt Sabourin
# License: MIT

"""
The MIT License

Copyright (c) 2011 Brett Cunningham, Matt Sabourin 

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

# import necessary libraries
from ssdeep import ssdeep  # for fuzzy hashing https://code.google.com/p/pyssdeep/
import pefile   # used to break up the PE file
import sys      # print to screen support
import sqlite3  # used to sqlite3 logging support
import hashlib  # used for MD5 support

# get to coding
debug = True	
ssd = ssdeep()                                  

try:
  filename = file(sys.argv[1])                    # make a file object
except IndexError:
  print "What file do you want me to analyze?"
  sys.exit()

md5v = hashlib.md5(filename.read()).hexdigest() # compute MD5 checksum of the entire binary, used as a way to identify which PE sections belong to other PE sections
unanalyzed = True

try:
  pe = pefile.PE(sys.argv[1])                     # make the file to be examined an object of the pefile library
  
  connection = sqlite3.connect('fuzzyhash.db')    # connect to database
  try:
    blah = connection.execute('''SELECT * FROM malware limit 1''') # see if sql table exist (must have at least one element in the DB for this to work :/ )
  except sqlite3.Error, e:
    connection.execute('''CREATE TABLE malware (id integer primary key autoincrement, md5 text, fuzzyhash text, apt boolean, malware boolean, actor text)''')  # creates SQL table if it doesn't exist

  tempcur = connection.cursor()
  t = (md5v,)
  blah = tempcur.execute('SELECT * FROM malware WHERE md5=?', t)

  if blah.fetchone() is not None:                   # this block of code is to check if the binary has already been submitted.
    print 'The binary with that MD5 has already been analyzed (MD5: %s)' % md5v
    unanalyzed = False

  ####### Break up PE File into sections, compute fuzzy hashes and store in database

  print "------------------------ File --------------------------"
  hashes1 = {}                                      # create a hash (that's what we call it in ruby anways), key = PE Section Name, value = computed fuzzy hash of the PE Section
  if debug: print 'MD5: %s' % md5v                  # print md5 of the entire program
  for section in pe.sections:
    if debug: sys.stdout.write(section.Name)        # print PE section name
    start = section.get_file_offset()
    hashes1[section.Name] = ssd.hash_bytes(section.get_data(start))     # compute fuzzy hash of PE section
    if debug: print ' %s' % hashes1[section.Name]   # print the fuzzy hash just computed
    cur = connection.cursor()                       # set up a cursor object for the DB connection
    ins = [(md5v, hashes1[section.Name], 'false', 'false')]  # put all variables into an array to be inserted into the sql table (i think it looks prettier in the code this way?)
    c = connection.execute('select * from malware where md5<>?', (md5v,)) # get all elements in the database for the next part
    print "------------------------ Similarity Comparison --------------------------"
    for row in c:
      likeness = ssd.compare(hashes1[section.Name], row[2])  # for everything in the database, compare it against the fuzzy hash just created
      if likeness > 1:                             # if it has over 30 (arbitrary) percent likeness, let it be known!
         print 'The binary with the MD5 of %s is %d percent similar to this one.' % (row[1], likeness)
         if row[3] == 1:
           print "which has been identified as APT"
         if row[4] == 1:
           print "which has been identified as generic malware"
    if unanalyzed: connection.execute('''insert into malware (md5, fuzzyhash, apt, malware) values (?,?,?,?)''', ins[0]) # insert the array into an sql table


  if unanalyzed: connection.commit()                # save changes to the database
  connection.close # close the database connection

except pefile.PEFormatError:
  print "Not a PE file"

