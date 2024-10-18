# MFTAH-CLI
Linux CLI application for MFTAH encapsulation and decapsulation (see https://github.com/NotsoanoNimus/MFTAH).

![image](https://github.com/user-attachments/assets/ecfa7b98-7c7d-47db-b906-8a0ad3ead2fd)


# Usage & Requirements
To compile and install the application, make sure you've installed the MFTAH dependency (link above). Once you've installed that, simply run `sudo make install_static` to put together a portable binary that you can copy-paste between systems. It is installed to `/usr/local/bin/mftahcrypt`.

The application comes with a pretty comprehensive `usage` display, accessed by `mftahcrypt --help`.

![Command Usage](https://github.com/user-attachments/assets/e4a144b4-f827-4d17-b92f-b9d4c1373558)

The application requires no dependencies except `pthread`.

Here's a sample of progress output when encrypting a Rocky Linux Live image of **about 1.8 GB**:

![File Processing with the Application](https://i.ibb.co/4VQn4Yz/Screencastfrom10-18-202404-16-09-PM1-ezgif-com-crop.gif)
