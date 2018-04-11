import fcntl
import os
import time

OUTPUT_FILE="/tmp/ludus_output"

def _get_locked_file_handle(filename):
  f=None
  while True:
    f=open(filename, "a+")
    fcntl.flock(f.fileno(), fcntl.LOCK_EX) #automatically unlocked when we close the handle.
    same_file=False
    #Make sure that the file was not deleted between opening and locking.
    try:
      if(os.stat(filename).st_ino==os.fstat(f.fileno()).st_ino): 
        same_file=True
    except OSError as e: 
      pass
    if same_file:
      break
    else:
      f.close()
      time.sleep(0.1)
  return f

#atomically saves the string.
def save_data(data, output_filename):
  if(len(data)==0):
    return True
  if data[-1]!="\n":
     data=data+"\n"
  #be sure that the file does not get too big.
  is_size_ok=True
  try:
    if(os.stat(output_filename).st_size > 5*1024*1024):
      is_size_ok=False
  except OSError as e: 
    #os.stat raises exception when file is not found. 
    #We cannot use file existence check because of race conditions...
    pass
    
  if(is_size_ok):
    f=_get_locked_file_handle(output_filename)
    f.write(data)
    f.close()
    return True
  return False