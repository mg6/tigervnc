/* Copyright (C) 2002-2005 RealVNC Ltd.  All Rights Reserved.
 * Copyright 2009-2011 Pierre Ossman <ossman@cendio.se> for Cendio AB
 * Copyright (C) 2011-2013 D. R. Commander.  All Rights Reserved.
 * Copyright (C) 2011-2013 Brian P. Hinz
 *
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this software; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA.
 */

//
// CConn
//
// Methods on CConn are called from both the GUI thread and the thread which
// processes incoming RFB messages ("the RFB thread").  This means we need to
// be careful with synchronization here.
//
// Any access to writer() must not only be synchronized, but we must also make
// sure that the connection is in RFBSTATE_NORMAL.  We are guaranteed this for
// any code called after serverInit() has been called.  Since the DesktopWindow
// isn't created until then, any methods called only from DesktopWindow can
// assume that we are in RFBSTATE_NORMAL.

package com.tigervnc.vncviewer;

import java.awt.*;
import java.awt.event.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import javax.swing.*;
import javax.swing.ImageIcon;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.util.*;

import com.tigervnc.rdr.*;
import com.tigervnc.rfb.*;
import com.tigervnc.rfb.Point;
import com.tigervnc.rfb.Exception;
import com.tigervnc.network.Socket;
import com.tigervnc.network.TcpSocket;

public class CConn extends CConnection
  implements UserPasswdGetter, UserMsgBox, OptionsDialogCallback, FdInStreamBlockCallback
{

  public final PixelFormat getPreferredPF() { return fullColourPF; }
  static final PixelFormat verylowColourPF = 
    new PixelFormat(8, 3, false, true, 1, 1, 1, 2, 1, 0);
  static final PixelFormat lowColourPF = 
    new PixelFormat(8, 6, false, true, 3, 3, 3, 4, 2, 0);
  static final PixelFormat mediumColourPF = 
    new PixelFormat(8, 8, false, false, 7, 7, 3, 0, 3, 6);
  static final int KEY_LOC_SHIFT_R = 0;
  static final int KEY_LOC_SHIFT_L = 16;
  static final int SUPER_MASK = 1<<15;

  ////////////////////////////////////////////////////////////////////
  // The following methods are all called from the RFB thread

  public CConn(VncViewer viewer_, Socket sock_,
               String vncServerName) 
  {
    serverHost = null; serverPort = 0; sock = sock_; viewer = viewer_; 
    pendingPFChange = false;
    currentEncoding = Encodings.encodingTight; lastServerEncoding = -1;
    fullColour = viewer.fullColour.getValue();
    lowColourLevel = viewer.lowColourLevel.getValue();
    autoSelect = viewer.autoSelect.getValue();
    formatChange = false; encodingChange = false;
    fullScreen = viewer.fullScreen.getValue();
    menuKeyCode = MenuKey.getMenuKeyCode();
    options = new OptionsDialog(this);
    options.initDialog();
    clipboardDialog = new ClipboardDialog(this);
    firstUpdate = true; pendingUpdate = false; continuousUpdates = false;
    forceNonincremental = true; supportsSyncFence = false;

    setShared(viewer.shared.getValue());
    upg = this;
    msg = this;

    String encStr = viewer.preferredEncoding.getValue();
    int encNum = Encodings.encodingNum(encStr);
    if (encNum != -1) {
      currentEncoding = encNum;
    }
    cp.supportsDesktopResize = true;
    cp.supportsExtendedDesktopSize = true;
    cp.supportsSetDesktopSize = true;
    cp.supportsClientRedirect = true;
    cp.supportsDesktopRename = true;
    cp.supportsLocalCursor = viewer.useLocalCursor.getValue();
    cp.customCompressLevel = viewer.customCompressLevel.getValue();
    cp.compressLevel = viewer.compressLevel.getValue();
    cp.noJpeg = viewer.noJpeg.getValue();
    cp.qualityLevel = viewer.qualityLevel.getValue();
    initMenu();

    if (sock != null) {
      String name = sock.getPeerEndpoint();
      vlog.info("Accepted connection from " + name);
    } else {
      if (vncServerName != null &&
          !viewer.alwaysShowServerDialog.getValue()) {
        serverHost = Hostname.getHost(vncServerName);
        serverPort = Hostname.getPort(vncServerName);
      } else {
        ServerDialog dlg = new ServerDialog(options, vncServerName, this);
        boolean ret = dlg.showDialog();
        if (!ret) {
          close();
          return;
        }
        serverHost = viewer.vncServerName.getValueStr();
        serverPort = viewer.vncServerPort.getValue();
      }

      try {
        sock = new TcpSocket(serverHost, serverPort);
      } catch (java.lang.Exception e) {
        throw new Exception(e.getMessage());
      }
      vlog.info("connected to host "+serverHost+" port "+serverPort);
    }

    sock.inStream().setBlockCallback(this);
    setServerName(serverHost);
    setStreams(sock.inStream(), sock.outStream());
    initialiseProtocol();
  }

  public void refreshFramebuffer()
  {
    forceNonincremental = true;

    // Without fences, we cannot safely trigger an update request directly
    // but must wait for the next update to arrive.
    if (supportsSyncFence)
      requestNewUpdate();
  }

  public boolean showMsgBox(int flags, String title, String text)
  {
    //StringBuffer titleText = new StringBuffer("VNC Viewer: "+title);
    return true;
  }

  // deleteWindow() is called when the user closes the desktop or menu windows.

  void deleteWindow() {
    if (viewport != null)
      viewport.dispose();
    viewport = null;
  }

  // blockCallback() is called when reading from the socket would block.
  public void blockCallback() {
    try {
      synchronized(this) {
        wait(1);
      }
    } catch (java.lang.InterruptedException e) {
      throw new Exception(e.getMessage());
    }
  }

  // getUserPasswd() is called by the CSecurity object when it needs us to read
  // a password from the user.

  public final boolean getUserPasswd(StringBuffer user, StringBuffer passwd) {
    String title = ("VNC Authentication ["
                    +csecurity.description() + "]");
    String passwordFileStr = viewer.passwordFile.getValue();
    PasswdDialog dlg;    

    if (user == null && passwordFileStr != "") {
      InputStream fp = null;
      try {
        fp = new FileInputStream(passwordFileStr);
      } catch(FileNotFoundException e) {
        throw new Exception("Opening password file failed");
      }
      byte[] obfPwd = new byte[256];
      try {
        fp.read(obfPwd);
        fp.close();
      } catch(IOException e) {
        throw new Exception("Failed to read VncPasswd file");
      }
      String PlainPasswd = VncAuth.unobfuscatePasswd(obfPwd);
      passwd.append(PlainPasswd);
      passwd.setLength(PlainPasswd.length());
      return true;
    }

    if (user == null) {
      dlg = new PasswdDialog(title, (user == null), (passwd == null));
    } else {
      if ((passwd == null) && viewer.sendLocalUsername.getValue()) {
         user.append((String)System.getProperties().get("user.name"));
         return true;
      }
      dlg = new PasswdDialog(title, viewer.sendLocalUsername.getValue(), 
         (passwd == null));
    }
    if (!dlg.showDialog()) return false;
    if (user != null) {
      if (viewer.sendLocalUsername.getValue()) {
         user.append((String)System.getProperties().get("user.name"));
      } else {
         user.append(dlg.userEntry.getText());
      }
    }
    if (passwd != null)
      passwd.append(new String(dlg.passwdEntry.getPassword()));
    return true;
  }

  // CConnection callback methods

  // serverInit() is called when the serverInit message has been received.  At
  // this point we create the desktop window and display it.  We also tell the
  // server the pixel format and encodings to use and request the first update.
  public void serverInit() {
    super.serverInit();

    // If using AutoSelect with old servers, start in FullColor
    // mode. See comment in autoSelectFormatAndEncoding. 
    if (cp.beforeVersion(3, 8) && autoSelect)
      fullColour = true;

    serverPF = cp.pf();

    desktop = new DesktopWindow(cp.width, cp.height, serverPF, this);
    fullColourPF = desktop.getPreferredPF();

    // Force a switch to the format and encoding we'd like
    formatChange = true; encodingChange = true;

    // And kick off the update cycle
    requestNewUpdate();

    // This initial update request is a bit of a corner case, so we need
    // to help out setting the correct format here.
    assert(pendingPFChange);
    desktop.setServerPF(pendingPF);
    cp.setPF(pendingPF);
    pendingPFChange = false;

    recreateViewport();
  }

  // setDesktopSize() is called when the desktop size changes (including when
  // it is set initially).
  public void setDesktopSize(int w, int h) {
    super.setDesktopSize(w, h);
    resizeFramebuffer();
  }

  // setExtendedDesktopSize() is a more advanced version of setDesktopSize()
  public void setExtendedDesktopSize(int reason, int result, int w, int h,
                                     ScreenSet layout) {
    super.setExtendedDesktopSize(reason, result, w, h, layout);

    if ((reason == screenTypes.reasonClient) &&
        (result != screenTypes.resultSuccess)) {
      vlog.error("SetDesktopSize failed: " + result);
      return;
    }

    resizeFramebuffer();
  }

  // clientRedirect() migrates the client to another host/port
  public void clientRedirect(int port, String host,
                             String x509subject) {
    try {
      sock.close();
      setServerPort(port);
      sock = new TcpSocket(host, port);
      vlog.info("Redirected to "+host+":"+port);
      VncViewer.newViewer(viewer, sock, true);
    } catch (java.lang.Exception e) {
      throw new Exception(e.getMessage());
    }
  }

  // setName() is called when the desktop name changes
  public void setName(String name) {
    super.setName(name);
  
    if (viewport != null) {
      viewport.setTitle(name+" - TigerVNC");
    }
  }

  // framebufferUpdateStart() is called at the beginning of an update.
  // Here we try to send out a new framebuffer update request so that the
  // next update can be sent out in parallel with us decoding the current
  // one. 
  public void framebufferUpdateStart() 
  {
    // Note: This might not be true if sync fences are supported
    pendingUpdate = false;

    requestNewUpdate();
  }

  // framebufferUpdateEnd() is called at the end of an update.
  // For each rectangle, the FdInStream will have timed the speed
  // of the connection, allowing us to select format and encoding
  // appropriately, and then request another incremental update.
  public void framebufferUpdateEnd() 
  {

    desktop.updateWindow();

    if (firstUpdate) {
      int width, height;
      
      // We need fences to make extra update requests and continuous
      // updates "safe". See fence() for the next step.
      if (cp.supportsFence)
        writer().writeFence(fenceTypes.fenceFlagRequest | fenceTypes.fenceFlagSyncNext, 0, null);

      if (cp.supportsSetDesktopSize &&
          viewer.desktopSize.getValue() != null &&
          viewer.desktopSize.getValue().split("x").length == 2) {
        width = Integer.parseInt(viewer.desktopSize.getValue().split("x")[0]);
        height = Integer.parseInt(viewer.desktopSize.getValue().split("x")[1]);
        ScreenSet layout;

        layout = cp.screenLayout;

        if (layout.num_screens() == 0)
          layout.add_screen(new Screen());
        else if (layout.num_screens() != 1) {

          while (true) {
            Iterator<Screen> iter = layout.screens.iterator(); 
            Screen screen = (Screen)iter.next();
        
            if (!iter.hasNext())
              break;

            layout.remove_screen(screen.id);
          }
        }

        Screen screen0 = (Screen)layout.screens.iterator().next();
        screen0.dimensions.tl.x = 0;
        screen0.dimensions.tl.y = 0;
        screen0.dimensions.br.x = width;
        screen0.dimensions.br.y = height;

        writer().writeSetDesktopSize(width, height, layout);
      }

      firstUpdate = false;
    }

    // A format change has been scheduled and we are now past the update
    // with the old format. Time to active the new one.
    if (pendingPFChange) {
      desktop.setServerPF(pendingPF);
      cp.setPF(pendingPF);
      pendingPFChange = false;
    }

    // Compute new settings based on updated bandwidth values
    if (autoSelect)
      autoSelectFormatAndEncoding();
  }

  // The rest of the callbacks are fairly self-explanatory...

  public void setColourMapEntries(int firstColour, int nColours, int[] rgbs) {
    desktop.setColourMapEntries(firstColour, nColours, rgbs);
  }

  public void bell() { 
    if (viewer.acceptBell.getValue())
      desktop.getToolkit().beep(); 
  }

  public void serverCutText(String str, int len) {
    if (viewer.acceptClipboard.getValue())
      clipboardDialog.serverCutText(str, len);
  }

  // We start timing on beginRect and stop timing on endRect, to
  // avoid skewing the bandwidth estimation as a result of the server
  // being slow or the network having high latency
  public void beginRect(Rect r, int encoding) {
    sock.inStream().startTiming();
    if (encoding != Encodings.encodingCopyRect) {
      lastServerEncoding = encoding;
    }
  }

  public void endRect(Rect r, int encoding) {
    sock.inStream().stopTiming();
  }

  public void fillRect(Rect r, int p) {
    desktop.fillRect(r.tl.x, r.tl.y, r.width(), r.height(), p);
  }

  public void imageRect(Rect r, Object p) {
    desktop.imageRect(r.tl.x, r.tl.y, r.width(), r.height(), p);
  }

  public void copyRect(Rect r, int sx, int sy) {
    desktop.copyRect(r.tl.x, r.tl.y, r.width(), r.height(), sx, sy);
  }

  public void setCursor(int width, int height, Point hotspot,
                        int[] data, byte[] mask) {
    desktop.setCursor(width, height, hotspot, data, mask);
  }

  public void fence(int flags, int len, byte[] data)
  {
    // can't call super.super.fence(flags, len, data);
    cp.supportsFence = true;

    if ((flags & fenceTypes.fenceFlagRequest) != 0) {
      // We handle everything synchronously so we trivially honor these modes
      flags = flags & (fenceTypes.fenceFlagBlockBefore | fenceTypes.fenceFlagBlockAfter);

      writer().writeFence(flags, len, data);
      return;
    }

    if (len == 0) {
      // Initial probe
      if ((flags & fenceTypes.fenceFlagSyncNext) != 0) {
        supportsSyncFence = true;

        if (cp.supportsContinuousUpdates) {
          vlog.info("Enabling continuous updates");
          continuousUpdates = true;
          writer().writeEnableContinuousUpdates(true, 0, 0, cp.width, cp.height);
        }
      }
    } else {
      // Pixel format change
      MemInStream memStream = new MemInStream(data, 0, len);
      PixelFormat pf = new PixelFormat();

      pf.read(memStream);

      desktop.setServerPF(pf);
      cp.setPF(pf);
    }
  }

  private void resizeFramebuffer()
  {
    if (desktop == null)
      return;

    if (continuousUpdates)
      writer().writeEnableContinuousUpdates(true, 0, 0, cp.width, cp.height);

    if ((cp.width == 0) && (cp.height == 0))
      return;
    if ((desktop.width() == cp.width) && (desktop.height() == cp.height))
      return;
    
    desktop.resize();
    recreateViewport();
  }

  // recreateViewport() recreates our top-level window.  This seems to be
  // better than attempting to resize the existing window, at least with
  // various X window managers.

  private void recreateViewport()
  {
    if (viewport != null) viewport.dispose();
    viewport = new Viewport(cp.name(), this);
    viewport.setUndecorated(fullScreen);
    desktop.setViewport(viewport);
    reconfigureViewport();
    if ((cp.width > 0) && (cp.height > 0))
      viewport.setVisible(true);
    desktop.requestFocusInWindow();
  }

  private void reconfigureViewport()
  {
    //viewport.setMaxSize(cp.width, cp.height);
    boolean pack = true;
    Dimension dpySize = viewport.getToolkit().getScreenSize();
    desktop.setScaledSize();
    int w = desktop.scaledWidth;
    int h = desktop.scaledHeight;
    GraphicsEnvironment ge =
      GraphicsEnvironment.getLocalGraphicsEnvironment();
    GraphicsDevice gd = ge.getDefaultScreenDevice();
    if (fullScreen) {
      viewport.setExtendedState(JFrame.MAXIMIZED_BOTH);
      viewport.setGeometry(0, 0, dpySize.width, dpySize.height, false);
      if (gd.isFullScreenSupported())
        gd.setFullScreenWindow(viewport);
    } else {
      int wmDecorationWidth = viewport.getInsets().left + viewport.getInsets().right;
      int wmDecorationHeight = viewport.getInsets().top + viewport.getInsets().bottom;
      if (w + wmDecorationWidth >= dpySize.width) {
        w = dpySize.width - wmDecorationWidth;
        pack = false;
      }
      if (h + wmDecorationHeight >= dpySize.height) {
        h = dpySize.height - wmDecorationHeight;
        pack = false;
      }

      if (viewport.getExtendedState() == JFrame.MAXIMIZED_BOTH) {
        w = viewport.getSize().width;
        h = viewport.getSize().height;
        int x = viewport.getLocation().x;
        int y = viewport.getLocation().y;
        viewport.setGeometry(x, y, w, h, pack);
      } else {
        int x = (dpySize.width - w - wmDecorationWidth) / 2;
        int y = (dpySize.height - h - wmDecorationHeight)/2;
        viewport.setExtendedState(JFrame.NORMAL);
        viewport.setGeometry(x, y, w, h, pack);
      }
      if (gd.isFullScreenSupported())
        gd.setFullScreenWindow(null);
    }
  }

  // autoSelectFormatAndEncoding() chooses the format and encoding appropriate
  // to the connection speed:
  //
  //   First we wait for at least one second of bandwidth measurement.
  //
  //   Above 16Mbps (i.e. LAN), we choose the second highest JPEG quality,
  //   which should be perceptually lossless.
  //
  //   If the bandwidth is below that, we choose a more lossy JPEG quality.
  //
  //   If the bandwidth drops below 256 Kbps, we switch to palette mode.
  //
  //   Note: The system here is fairly arbitrary and should be replaced
  //         with something more intelligent at the server end.
  //
  private void autoSelectFormatAndEncoding() {
    long kbitsPerSecond = sock.inStream().kbitsPerSecond();
    long timeWaited = sock.inStream().timeWaited();
    boolean newFullColour = fullColour;
    int newQualityLevel = cp.qualityLevel;

    // Always use Tight
    if (currentEncoding != Encodings.encodingTight) {
      currentEncoding = Encodings.encodingTight;
      encodingChange = true;
    }

    // Check that we have a decent bandwidth measurement
    if ((kbitsPerSecond == 0) || (timeWaited < 100))
      return;
  
    // Select appropriate quality level
    if (!cp.noJpeg) {
      if (kbitsPerSecond > 16000)
        newQualityLevel = 8;
      else
        newQualityLevel = 6;
  
      if (newQualityLevel != cp.qualityLevel) {
        vlog.info("Throughput "+kbitsPerSecond+
                  " kbit/s - changing to quality "+newQualityLevel);
        cp.qualityLevel = newQualityLevel;
        viewer.qualityLevel.setParam(Integer.toString(newQualityLevel));
        encodingChange = true;
      }
    }

    if (cp.beforeVersion(3, 8)) {
      // Xvnc from TightVNC 1.2.9 sends out FramebufferUpdates with
      // cursors "asynchronously". If this happens in the middle of a
      // pixel format change, the server will encode the cursor with
      // the old format, but the client will try to decode it
      // according to the new format. This will lead to a
      // crash. Therefore, we do not allow automatic format change for
      // old servers.
      return;
    }
    
    // Select best color level
    newFullColour = (kbitsPerSecond > 256);
    if (newFullColour != fullColour) {
      vlog.info("Throughput "+kbitsPerSecond+
                " kbit/s - full color is now "+ 
  	            (newFullColour ? "enabled" : "disabled"));
      fullColour = newFullColour;
      formatChange = true;
      forceNonincremental = true;
    } 
  }

  // requestNewUpdate() requests an update from the server, having set the
  // format and encoding appropriately.
  private void requestNewUpdate()
  {
    if (formatChange) {
      PixelFormat pf;

      /* Catch incorrect requestNewUpdate calls */
      assert(!pendingUpdate || supportsSyncFence);

      if (fullColour) {
        pf = fullColourPF;
      } else {
        if (lowColourLevel == 0) {
          pf = verylowColourPF;
        } else if (lowColourLevel == 1) {
          pf = lowColourPF;
        } else {
          pf = mediumColourPF;
        }
      }

      if (supportsSyncFence) {
        // We let the fence carry the pixel format and switch once we
        // get the response back. That way we will be synchronised with
        // when the server switches.
        MemOutStream memStream = new MemOutStream();

        pf.write(memStream);

        writer().writeFence(fenceTypes.fenceFlagRequest | fenceTypes.fenceFlagSyncNext,
                            memStream.length(), (byte[])memStream.data());
      } else {
        // New requests are sent out at the start of processing the last
        // one, so we cannot switch our internal format right now (doing so
        // would mean misdecoding the current update).
        pendingPFChange = true;
        pendingPF = pf;
      }

      String str = pf.print();
      vlog.info("Using pixel format " + str);
      writer().writeSetPixelFormat(pf);

      formatChange = false;
    }

    checkEncodings();

    if (forceNonincremental || !continuousUpdates) {
      pendingUpdate = true;
      writer().writeFramebufferUpdateRequest(new Rect(0, 0, cp.width, cp.height),
                                                 !forceNonincremental);
    }

    forceNonincremental = false;
  }


  ////////////////////////////////////////////////////////////////////
  // The following methods are all called from the GUI thread

  // close() shuts down the socket, thus waking up the RFB thread.
  public void close() {
    deleteWindow();
    shuttingDown = true;
    try {
      if (sock != null)
        sock.shutdown();
    } catch (java.lang.Exception e) {
      throw new Exception(e.getMessage());
    }
  }

  // Menu callbacks.  These are guaranteed only to be called after serverInit()
  // has been called, since the menu is only accessible from the DesktopWindow

  private void initMenu() {
    menu = new F8Menu(this);
  }

  void showMenu(int x, int y) {
    String os = System.getProperty("os.name");
    if (os.startsWith("Windows"))
      com.sun.java.swing.plaf.windows.WindowsLookAndFeel.setMnemonicHidden(false);
    menu.show(desktop, x, y);
  }

  void showAbout() {
    String pkgDate = "";
    String pkgTime = "";
    try {
      Manifest manifest = new Manifest(VncViewer.timestamp);
      Attributes attributes = manifest.getMainAttributes();
      pkgDate = attributes.getValue("Package-Date");
      pkgTime = attributes.getValue("Package-Time");
    } catch (IOException e) { }

    Window fullScreenWindow = Viewport.getFullScreenWindow();
    if (fullScreenWindow != null)
      Viewport.setFullScreenWindow(null);
    String msg = 
      String.format(VncViewer.aboutText, VncViewer.version, VncViewer.build,
                    VncViewer.buildDate, VncViewer.buildTime);
    JOptionPane op = 
      new JOptionPane(msg, JOptionPane.INFORMATION_MESSAGE,
                      JOptionPane.DEFAULT_OPTION, VncViewer.logoIcon);
    JDialog dlg = op.createDialog("About TigerVNC Viewer for Java");
    dlg.setIconImage(VncViewer.frameIcon);
    dlg.setVisible(true);
    if (fullScreenWindow != null)
      Viewport.setFullScreenWindow(fullScreenWindow);
  }

  void showInfo() {
    Window fullScreenWindow = Viewport.getFullScreenWindow();
    if (fullScreenWindow != null)
      Viewport.setFullScreenWindow(null);
    String info = new String("Desktop name: %s%n"+
                             "Host: %s:%d%n"+
                             "Size: %dx%d%n"+
                             "Pixel format: %s%n"+
                             "  (server default: %s)%n"+
                             "Requested encoding: %s%n"+
                             "Last used encoding: %s%n"+
                             "Line speed estimate: %d kbit/s%n"+
                             "Protocol version: %d.%d%n"+
                             "Security method: %s [%s]%n");
    String msg = 
      String.format(info, cp.name(),
                    sock.getPeerName(), sock.getPeerPort(),
                    cp.width, cp.height,
                    desktop.getPF().print(),
                    serverPF.print(),
                    Encodings.encodingName(currentEncoding),
                    Encodings.encodingName(lastServerEncoding),
                    sock.inStream().kbitsPerSecond(),
                    cp.majorVersion, cp.minorVersion,
                    Security.secTypeName(csecurity.getType()),
                    csecurity.description());
    JOptionPane op = new JOptionPane(msg, JOptionPane.PLAIN_MESSAGE,
                                     JOptionPane.DEFAULT_OPTION);
    JDialog dlg = op.createDialog("VNC connection info");
    dlg.setIconImage(VncViewer.frameIcon);
    dlg.setVisible(true);
    if (fullScreenWindow != null)
      Viewport.setFullScreenWindow(fullScreenWindow);
  }

  public void refresh() {
    writer().writeFramebufferUpdateRequest(new Rect(0,0,cp.width,cp.height), false);
    pendingUpdate = true;
  }


  // OptionsDialogCallback.  setOptions() sets the options dialog's checkboxes
  // etc to reflect our flags.  getOptions() sets our flags according to the
  // options dialog's checkboxes.  They are both called from the GUI thread.
  // Some of the flags are also accessed by the RFB thread.  I believe that
  // reading and writing boolean and int values in java is atomic, so there is
  // no need for synchronization.

  public void setOptions() {
    int digit;
    options.autoSelect.setSelected(autoSelect);
    options.fullColour.setSelected(fullColour);
    options.veryLowColour.setSelected(!fullColour && lowColourLevel == 0);
    options.lowColour.setSelected(!fullColour && lowColourLevel == 1);
    options.mediumColour.setSelected(!fullColour && lowColourLevel == 2);
    options.tight.setSelected(currentEncoding == Encodings.encodingTight);
    options.zrle.setSelected(currentEncoding == Encodings.encodingZRLE);
    options.hextile.setSelected(currentEncoding == Encodings.encodingHextile);
    options.raw.setSelected(currentEncoding == Encodings.encodingRaw);

    options.customCompressLevel.setSelected(viewer.customCompressLevel.getValue());
    digit = 0 + viewer.compressLevel.getValue();
    if (digit >= 0 && digit <= 9) {
      options.compressLevel.setSelectedItem(digit);
    } else {
      options.compressLevel.setSelectedItem(Integer.parseInt(viewer.compressLevel.getDefaultStr()));
    }
    options.noJpeg.setSelected(!viewer.noJpeg.getValue());
    digit = 0 + viewer.qualityLevel.getValue();
    if (digit >= 0 && digit <= 9) {
      options.qualityLevel.setSelectedItem(digit);
    } else {
      options.qualityLevel.setSelectedItem(Integer.parseInt(viewer.qualityLevel.getDefaultStr()));
    }

    options.viewOnly.setSelected(viewer.viewOnly.getValue());
    options.acceptClipboard.setSelected(viewer.acceptClipboard.getValue());
    options.sendClipboard.setSelected(viewer.sendClipboard.getValue());
    options.menuKey.setSelectedItem(KeyEvent.getKeyText(MenuKey.getMenuKeyCode()));
    options.sendLocalUsername.setSelected(viewer.sendLocalUsername.getValue());

    if (state() == RFBSTATE_NORMAL) {
      options.shared.setEnabled(false);
      options.secVeNCrypt.setEnabled(false);
      options.encNone.setEnabled(false);
      options.encTLS.setEnabled(false);
      options.encX509.setEnabled(false);
      options.ca.setEnabled(false);
      options.crl.setEnabled(false);
      options.secIdent.setEnabled(false);
      options.secNone.setEnabled(false);
      options.secVnc.setEnabled(false);
      options.secPlain.setEnabled(false);
      options.sendLocalUsername.setEnabled(false);
      options.cfLoadButton.setEnabled(false);
      options.cfSaveAsButton.setEnabled(true);
    } else {
      options.shared.setSelected(viewer.shared.getValue());
      options.sendLocalUsername.setSelected(viewer.sendLocalUsername.getValue());
      options.cfSaveAsButton.setEnabled(false);

      /* Process non-VeNCrypt sectypes */
      java.util.List<Integer> secTypes = new ArrayList<Integer>();
      secTypes = Security.GetEnabledSecTypes();
      for (Iterator<Integer> i = secTypes.iterator(); i.hasNext();) {
        switch ((Integer)i.next()) {
        case Security.secTypeVeNCrypt:
          options.secVeNCrypt.setSelected(UserPreferences.getBool("viewer", "secVeNCrypt", true));
          break;
        case Security.secTypeNone:
          options.encNone.setSelected(true);
          options.secNone.setSelected(UserPreferences.getBool("viewer", "secTypeNone", true));
          break;
        case Security.secTypeVncAuth:
          options.encNone.setSelected(true);
          options.secVnc.setSelected(UserPreferences.getBool("viewer", "secTypeVncAuth", true));
          break;
        }
      }

      /* Process VeNCrypt subtypes */
      if (options.secVeNCrypt.isSelected()) {
        java.util.List<Integer> secTypesExt = new ArrayList<Integer>();
        secTypesExt = Security.GetEnabledExtSecTypes();
        for (Iterator<Integer> iext = secTypesExt.iterator(); iext.hasNext();) {
          switch ((Integer)iext.next()) {
          case Security.secTypePlain:
            options.encNone.setSelected(UserPreferences.getBool("viewer", "encNone", true));
            options.secPlain.setSelected(UserPreferences.getBool("viewer", "secPlain", true));
            break;
          case Security.secTypeIdent:
            options.encNone.setSelected(UserPreferences.getBool("viewer", "encNone", true));
            options.secIdent.setSelected(UserPreferences.getBool("viewer", "secIdent", true));
            break;
          case Security.secTypeTLSNone:
            options.encTLS.setSelected(UserPreferences.getBool("viewer", "encTLS", true));
            options.secNone.setSelected(UserPreferences.getBool("viewer", "secNone", true));
            break;
          case Security.secTypeTLSVnc:
            options.encTLS.setSelected(UserPreferences.getBool("viewer", "encTLS", true));
            options.secVnc.setSelected(UserPreferences.getBool("viewer", "secVnc", true));
            break;
          case Security.secTypeTLSPlain:
            options.encTLS.setSelected(UserPreferences.getBool("viewer", "encTLS", true));
            options.secPlain.setSelected(UserPreferences.getBool("viewer", "secPlain", true));
            break;
          case Security.secTypeTLSIdent:
            options.encTLS.setSelected(UserPreferences.getBool("viewer", "encTLS", true));
            options.secIdent.setSelected(UserPreferences.getBool("viewer", "secIdent", true));
            break;
          case Security.secTypeX509None:
            options.encX509.setSelected(UserPreferences.getBool("viewer", "encX509", true));
            options.secNone.setSelected(UserPreferences.getBool("viewer", "secNone", true));
            break;
          case Security.secTypeX509Vnc:
            options.encX509.setSelected(UserPreferences.getBool("viewer", "encX509", true));
            options.secVnc.setSelected(UserPreferences.getBool("viewer", "secVnc", true));
            break;
          case Security.secTypeX509Plain:
            options.encX509.setSelected(UserPreferences.getBool("viewer", "encX509", true));
            options.secPlain.setSelected(UserPreferences.getBool("viewer", "secPlain", true));
            break;
          case Security.secTypeX509Ident:
            options.encX509.setSelected(UserPreferences.getBool("viewer", "encX509", true));
            options.secIdent.setSelected(UserPreferences.getBool("viewer", "secIdent", true));
            break;
          }
        }
      }
      options.encNone.setEnabled(options.secVeNCrypt.isSelected());
      options.encTLS.setEnabled(options.secVeNCrypt.isSelected());
      options.encX509.setEnabled(options.secVeNCrypt.isSelected());
      options.ca.setEnabled(options.secVeNCrypt.isSelected());
      options.crl.setEnabled(options.secVeNCrypt.isSelected());
      options.secIdent.setEnabled(options.secVeNCrypt.isSelected());
      options.secPlain.setEnabled(options.secVeNCrypt.isSelected());
      options.sendLocalUsername.setEnabled(options.secPlain.isSelected()||
        options.secIdent.isSelected());
    }

    options.fullScreen.setSelected(fullScreen);
    options.useLocalCursor.setSelected(viewer.useLocalCursor.getValue());
    options.acceptBell.setSelected(viewer.acceptBell.getValue());
    String scaleString = viewer.scalingFactor.getValue();
    if (scaleString.equalsIgnoreCase("Auto")) {
      options.scalingFactor.setSelectedItem("Auto");
    } else if(scaleString.equalsIgnoreCase("FixedRatio")) {
      options.scalingFactor.setSelectedItem("Fixed Aspect Ratio");
    } else { 
      digit = Integer.parseInt(scaleString);
      if (digit >= 1 && digit <= 1000) {
        options.scalingFactor.setSelectedItem(digit+"%");
      } else {
        digit = Integer.parseInt(viewer.scalingFactor.getDefaultStr());
        options.scalingFactor.setSelectedItem(digit+"%");
      }
      int scaleFactor = 
        Integer.parseInt(scaleString.substring(0, scaleString.length()));
      if (desktop != null)
        desktop.setScaledSize();
    }
  }

  public void getOptions() {
    autoSelect = options.autoSelect.isSelected();
    if (fullColour != options.fullColour.isSelected()) {
      formatChange = true;
      forceNonincremental = true;
    }
    fullColour = options.fullColour.isSelected();
    if (!fullColour) {
      int newLowColourLevel = (options.veryLowColour.isSelected() ? 0 :
                               options.lowColour.isSelected() ? 1 : 2);
      if (newLowColourLevel != lowColourLevel) {
        lowColourLevel = newLowColourLevel;
        formatChange = true;
        forceNonincremental = true;
      }
    }
    int newEncoding = (options.zrle.isSelected() ?  Encodings.encodingZRLE :
                       options.hextile.isSelected() ?  Encodings.encodingHextile :
                       options.tight.isSelected() ?  Encodings.encodingTight :
                       Encodings.encodingRaw);
    if (newEncoding != currentEncoding) {
      currentEncoding = newEncoding;
      encodingChange = true;
    }

    viewer.customCompressLevel.setParam(options.customCompressLevel.isSelected());
    if (cp.customCompressLevel != viewer.customCompressLevel.getValue()) {
      cp.customCompressLevel = viewer.customCompressLevel.getValue();
      encodingChange = true;
    }
    if (Integer.parseInt(options.compressLevel.getSelectedItem().toString()) >= 0 && 
        Integer.parseInt(options.compressLevel.getSelectedItem().toString()) <= 9) {
      viewer.compressLevel.setParam(options.compressLevel.getSelectedItem().toString());
    } else {
      viewer.compressLevel.setParam(viewer.compressLevel.getDefaultStr());
    }
    if (cp.compressLevel != viewer.compressLevel.getValue()) {
      cp.compressLevel = viewer.compressLevel.getValue();
      encodingChange = true;
    }
    viewer.noJpeg.setParam(!options.noJpeg.isSelected());
    if (cp.noJpeg != viewer.noJpeg.getValue()) {
      cp.noJpeg = viewer.noJpeg.getValue();
      encodingChange = true;
    }
    viewer.qualityLevel.setParam(options.qualityLevel.getSelectedItem().toString());
    if (cp.qualityLevel != viewer.qualityLevel.getValue()) {
      cp.qualityLevel = viewer.qualityLevel.getValue();
      encodingChange = true;
    }
    viewer.sendLocalUsername.setParam(options.sendLocalUsername.isSelected());

    viewer.viewOnly.setParam(options.viewOnly.isSelected());
    viewer.acceptClipboard.setParam(options.acceptClipboard.isSelected());
    viewer.sendClipboard.setParam(options.sendClipboard.isSelected());
    viewer.acceptBell.setParam(options.acceptBell.isSelected());
    String scaleString =
      options.scalingFactor.getSelectedItem().toString();
    String oldScaleFactor = viewer.scalingFactor.getValue();
    if (scaleString.equalsIgnoreCase("Fixed Aspect Ratio")) {
      scaleString = new String("FixedRatio");
    } else if (scaleString.equalsIgnoreCase("Auto")) {
      scaleString = new String("Auto");
    } else {
      scaleString=scaleString.substring(0, scaleString.length()-1);
    }
    if (!oldScaleFactor.equals(scaleString)) {
      viewer.scalingFactor.setParam(scaleString);
      if ((options.fullScreen.isSelected() == fullScreen) &&
          (desktop != null))
        recreateViewport();
    }

    clipboardDialog.setSendingEnabled(viewer.sendClipboard.getValue());
    viewer.menuKey.setParam(MenuKey.getMenuKeySymbols()[options.menuKey.getSelectedIndex()].name);
    F8Menu.f8.setText("Send "+KeyEvent.getKeyText(MenuKey.getMenuKeyCode()));

    setShared(options.shared.isSelected());
    viewer.useLocalCursor.setParam(options.useLocalCursor.isSelected());
    if (cp.supportsLocalCursor != viewer.useLocalCursor.getValue()) {
      cp.supportsLocalCursor = viewer.useLocalCursor.getValue();
      encodingChange = true;
      if (desktop != null)
        desktop.resetLocalCursor();
    }

    checkEncodings();

    if (state() != RFBSTATE_NORMAL) {
      /* Process security types which don't use encryption */
      if (options.encNone.isSelected()) {
        if (options.secNone.isSelected())
          Security.EnableSecType(Security.secTypeNone);
        if (options.secVnc.isSelected())
          Security.EnableSecType(Security.secTypeVncAuth);
        if (options.secPlain.isSelected())
          Security.EnableSecType(Security.secTypePlain);
        if (options.secIdent.isSelected())
          Security.EnableSecType(Security.secTypeIdent);
      } else {
        Security.DisableSecType(Security.secTypeNone);
        Security.DisableSecType(Security.secTypeVncAuth);
        Security.DisableSecType(Security.secTypePlain);
        Security.DisableSecType(Security.secTypeIdent);
      }

      /* Process security types which use TLS encryption */
      if (options.encTLS.isSelected()) {
        if (options.secNone.isSelected())
          Security.EnableSecType(Security.secTypeTLSNone);
        if (options.secVnc.isSelected())
          Security.EnableSecType(Security.secTypeTLSVnc);
        if (options.secPlain.isSelected())
          Security.EnableSecType(Security.secTypeTLSPlain);
        if (options.secIdent.isSelected())
          Security.EnableSecType(Security.secTypeTLSIdent);
      } else {
        Security.DisableSecType(Security.secTypeTLSNone);
        Security.DisableSecType(Security.secTypeTLSVnc);
        Security.DisableSecType(Security.secTypeTLSPlain);
        Security.DisableSecType(Security.secTypeTLSIdent);
      }
  
      /* Process security types which use X509 encryption */
      if (options.encX509.isSelected()) {
        if (options.secNone.isSelected())
          Security.EnableSecType(Security.secTypeX509None);
        if (options.secVnc.isSelected())
          Security.EnableSecType(Security.secTypeX509Vnc);
        if (options.secPlain.isSelected())
          Security.EnableSecType(Security.secTypeX509Plain);
        if (options.secIdent.isSelected())
          Security.EnableSecType(Security.secTypeX509Ident);
      } else {
        Security.DisableSecType(Security.secTypeX509None);
        Security.DisableSecType(Security.secTypeX509Vnc);
        Security.DisableSecType(Security.secTypeX509Plain);
        Security.DisableSecType(Security.secTypeX509Ident);
      }
  
      /* Process *None security types */
      if (options.secNone.isSelected()) {
        if (options.encNone.isSelected())
          Security.EnableSecType(Security.secTypeNone);
        if (options.encTLS.isSelected())
          Security.EnableSecType(Security.secTypeTLSNone);
        if (options.encX509.isSelected())
          Security.EnableSecType(Security.secTypeX509None);
      } else {
        Security.DisableSecType(Security.secTypeNone);
        Security.DisableSecType(Security.secTypeTLSNone);
        Security.DisableSecType(Security.secTypeX509None);
      }
  
      /* Process *Vnc security types */
      if (options.secVnc.isSelected()) {
        if (options.encNone.isSelected())
          Security.EnableSecType(Security.secTypeVncAuth);
        if (options.encTLS.isSelected())
          Security.EnableSecType(Security.secTypeTLSVnc);
        if (options.encX509.isSelected())
          Security.EnableSecType(Security.secTypeX509Vnc);
      } else {
        Security.DisableSecType(Security.secTypeVncAuth);
        Security.DisableSecType(Security.secTypeTLSVnc);
        Security.DisableSecType(Security.secTypeX509Vnc);
      }
  
      /* Process *Plain security types */
      if (options.secPlain.isSelected()) {
        if (options.encNone.isSelected())
          Security.EnableSecType(Security.secTypePlain);
        if (options.encTLS.isSelected())
          Security.EnableSecType(Security.secTypeTLSPlain);
        if (options.encX509.isSelected())
          Security.EnableSecType(Security.secTypeX509Plain);
      } else {
        Security.DisableSecType(Security.secTypePlain);
        Security.DisableSecType(Security.secTypeTLSPlain);
        Security.DisableSecType(Security.secTypeX509Plain);
      }
  
      /* Process *Ident security types */
      if (options.secIdent.isSelected()) {
        if (options.encNone.isSelected())
          Security.EnableSecType(Security.secTypeIdent);
        if (options.encTLS.isSelected())
          Security.EnableSecType(Security.secTypeTLSIdent);
        if (options.encX509.isSelected())
          Security.EnableSecType(Security.secTypeX509Ident);
      } else {
        Security.DisableSecType(Security.secTypeIdent);
        Security.DisableSecType(Security.secTypeTLSIdent);
        Security.DisableSecType(Security.secTypeX509Ident);
      }
    }
    if (options.fullScreen.isSelected() ^ fullScreen)
      toggleFullScreen();
  }

  public void toggleFullScreen() {
    fullScreen = !fullScreen;
    menu.fullScreen.setSelected(fullScreen);
    if (viewport != null)
      recreateViewport();
  }

  // writeClientCutText() is called from the clipboard dialog
  public void writeClientCutText(String str, int len) {
    if (state() != RFBSTATE_NORMAL || shuttingDown)
      return;
    writer().writeClientCutText(str, len);
  }

  public void writeKeyEvent(int keysym, boolean down) {
    if (state() != RFBSTATE_NORMAL || shuttingDown)
      return;
    writer().writeKeyEvent(keysym, down);
  }

  public void writeKeyEvent(KeyEvent ev, int keysym) {
    if (keysym < 0)
      return;
    String fmt = ev.paramString().replaceAll("%","%%");
    vlog.debug(String.format(fmt.replaceAll(",","%n       ")));
    // Windows sends an extra CTRL_L + ALT_R when AltGr is down that need to
    // be suppressed for keyTyped events. In Java 6 KeyEvent.isAltGraphDown()
    // is broken for keyPressed/keyReleased events.
    int ALTGR_MASK = ((Event.CTRL_MASK<<KEY_LOC_SHIFT_L) | Event.ALT_MASK);
    String os = System.getProperty("os.name");
    if (os.startsWith("Windows") && ((modifiers & ALTGR_MASK) != 0)) {
      writeKeyEvent(Keysyms.Control_L, false);
      writeKeyEvent(Keysyms.Alt_R, false);
      writeKeyEvent(keysym, true);
      writeKeyEvent(keysym, false);
      writeKeyEvent(Keysyms.Control_L, true);
      writeKeyEvent(Keysyms.Alt_R, true);
    } else {
      writeKeyEvent(keysym, true);
      writeKeyEvent(keysym, false);
    }
  }

  public void writeKeyEvent(KeyEvent ev) {
    int keysym = 0, keycode, key, location, locationShift;

    if (shuttingDown)
      return;

    boolean down = (ev.getID() == KeyEvent.KEY_PRESSED);

    keycode = ev.getKeyCode();
    if (keycode == KeyEvent.VK_UNDEFINED)
      return;
    key = ev.getKeyChar();
    location = ev.getKeyLocation();
    if (location == KeyEvent.KEY_LOCATION_RIGHT)
      locationShift = KEY_LOC_SHIFT_R;
    else
      locationShift = KEY_LOC_SHIFT_L;

    if (!ev.isActionKey()) {
      if (keycode >= KeyEvent.VK_0 && keycode <= KeyEvent.VK_9 &&
        location == KeyEvent.KEY_LOCATION_NUMPAD)
        keysym = Keysyms.KP_0 + keycode - KeyEvent.VK_0;

      switch (keycode) {
      case KeyEvent.VK_BACK_SPACE: keysym = Keysyms.BackSpace; break;
      case KeyEvent.VK_TAB:        keysym = Keysyms.Tab; break;
      case KeyEvent.VK_ENTER:
        if (location == KeyEvent.KEY_LOCATION_NUMPAD)
          keysym = Keysyms.KP_Enter;
        else
          keysym = Keysyms.Return;  break;
      case KeyEvent.VK_ESCAPE:     keysym = Keysyms.Escape; break;
      case KeyEvent.VK_NUMPAD0:    keysym = Keysyms.KP_0; break;
      case KeyEvent.VK_NUMPAD1:    keysym = Keysyms.KP_1; break;
      case KeyEvent.VK_NUMPAD2:    keysym = Keysyms.KP_2; break;
      case KeyEvent.VK_NUMPAD3:    keysym = Keysyms.KP_3; break;
      case KeyEvent.VK_NUMPAD4:    keysym = Keysyms.KP_4; break;
      case KeyEvent.VK_NUMPAD5:    keysym = Keysyms.KP_5; break;
      case KeyEvent.VK_NUMPAD6:    keysym = Keysyms.KP_6; break;
      case KeyEvent.VK_NUMPAD7:    keysym = Keysyms.KP_7; break;
      case KeyEvent.VK_NUMPAD8:    keysym = Keysyms.KP_8; break;
      case KeyEvent.VK_NUMPAD9:    keysym = Keysyms.KP_9; break;
      case KeyEvent.VK_DECIMAL:    keysym = Keysyms.KP_Decimal; break;
      case KeyEvent.VK_ADD:        keysym = Keysyms.KP_Add; break;
      case KeyEvent.VK_SUBTRACT:   keysym = Keysyms.KP_Subtract; break;
      case KeyEvent.VK_MULTIPLY:   keysym = Keysyms.KP_Multiply; break;
      case KeyEvent.VK_DIVIDE:     keysym = Keysyms.KP_Divide; break;
      case KeyEvent.VK_DELETE:
        if (location == KeyEvent.KEY_LOCATION_NUMPAD)
          keysym = Keysyms.KP_Delete;
        else
          keysym = Keysyms.Delete;  break;
      case KeyEvent.VK_CLEAR:
        if (location == KeyEvent.KEY_LOCATION_NUMPAD)
          keysym = Keysyms.KP_Begin;
        else
          keysym = Keysyms.Clear;  break;
      case KeyEvent.VK_CONTROL:
        if (down)
          modifiers |= (Event.CTRL_MASK<<locationShift);
        else
          modifiers &= ~(Event.CTRL_MASK<<locationShift);
        if (location == KeyEvent.KEY_LOCATION_RIGHT)
          keysym = Keysyms.Control_R;
        else
          keysym = Keysyms.Control_L;  break;
      case KeyEvent.VK_ALT:
        if (down)
          modifiers |= (Event.ALT_MASK<<locationShift);
        else
          modifiers &= ~(Event.ALT_MASK<<locationShift);
        if (location == KeyEvent.KEY_LOCATION_RIGHT)
          keysym = Keysyms.Alt_R;
        else
          keysym = Keysyms.Alt_L;  break;
      case KeyEvent.VK_SHIFT:
        if (down)
          modifiers |= (Event.SHIFT_MASK<<locationShift);
        else
          modifiers &= ~(Event.SHIFT_MASK<<locationShift);
        if (location == KeyEvent.KEY_LOCATION_RIGHT)
          keysym = Keysyms.Shift_R;
        else
          keysym = Keysyms.Shift_L;  break;
      case KeyEvent.VK_META:
        if (down)
          modifiers |= (Event.META_MASK<<locationShift);
        else
          modifiers &= ~(Event.META_MASK<<locationShift);
        if (location == KeyEvent.KEY_LOCATION_RIGHT)
          keysym = Keysyms.Meta_R;
        else
          keysym = Keysyms.Meta_L;  break;
      default:
        if (ev.isControlDown()) {
          // For CTRL-<letter>, CTRL is sent separately, so just send <letter>.
          if ((key >= 1 && key <= 26 && !ev.isShiftDown()) ||
              // CTRL-{, CTRL-|, CTRL-} also map to ASCII 96-127
              (key >= 27 && key <= 29 && ev.isShiftDown()))
            key += 96;
          // For CTRL-SHIFT-<letter>, send capital <letter> to emulate behavior
          // of Linux.  For CTRL-@, send @.  For CTRL-_, send _.  For CTRL-^,
          // send ^.
          else if (key < 32)
            key += 64;
          // Windows and Mac sometimes return CHAR_UNDEFINED with CTRL-SHIFT
          // combinations, so best we can do is send the key code if it is
          // a valid ASCII symbol.
          else if (key == KeyEvent.CHAR_UNDEFINED && keycode >= 0 &&
                   keycode <= 127)
            key = keycode;
        }

        keysym = UnicodeToKeysym.translate(key);
        if (keysym == -1)
          return;
      }
    } else {
      // KEY_ACTION
      switch (keycode) {
      case KeyEvent.VK_HOME:
        if (location == KeyEvent.KEY_LOCATION_NUMPAD)
          keysym = Keysyms.KP_Home;
        else
          keysym = Keysyms.Home;  break;
      case KeyEvent.VK_END:
        if (location == KeyEvent.KEY_LOCATION_NUMPAD)
          keysym = Keysyms.KP_End;
        else
          keysym = Keysyms.End;  break;
      case KeyEvent.VK_PAGE_UP:
        if (location == KeyEvent.KEY_LOCATION_NUMPAD)
          keysym = Keysyms.KP_Page_Up;
        else
          keysym = Keysyms.Page_Up;  break;
      case KeyEvent.VK_PAGE_DOWN:
        if (location == KeyEvent.KEY_LOCATION_NUMPAD)
          keysym = Keysyms.KP_Page_Down;
        else
          keysym = Keysyms.Page_Down;  break;
      case KeyEvent.VK_UP:
        if (location == KeyEvent.KEY_LOCATION_NUMPAD)
          keysym = Keysyms.KP_Up;
        else
          keysym = Keysyms.Up;  break;
      case KeyEvent.VK_DOWN:
        if (location == KeyEvent.KEY_LOCATION_NUMPAD)
          keysym = Keysyms.KP_Down;
        else
         keysym = Keysyms.Down;  break;
      case KeyEvent.VK_LEFT:
        if (location == KeyEvent.KEY_LOCATION_NUMPAD)
          keysym = Keysyms.KP_Left;
        else
         keysym = Keysyms.Left;  break;
      case KeyEvent.VK_RIGHT:
        if (location == KeyEvent.KEY_LOCATION_NUMPAD)
          keysym = Keysyms.KP_Right;
        else
          keysym = Keysyms.Right;  break;
      case KeyEvent.VK_BEGIN:
        if (location == KeyEvent.KEY_LOCATION_NUMPAD)
          keysym = Keysyms.KP_Begin;
        else
          keysym = Keysyms.Begin;  break;
      case KeyEvent.VK_KP_LEFT:      keysym = Keysyms.KP_Left; break;
      case KeyEvent.VK_KP_UP:        keysym = Keysyms.KP_Up; break;
      case KeyEvent.VK_KP_RIGHT:     keysym = Keysyms.KP_Right; break;
      case KeyEvent.VK_KP_DOWN:      keysym = Keysyms.KP_Down; break;
      case KeyEvent.VK_F1:           keysym = Keysyms.F1; break;
      case KeyEvent.VK_F2:           keysym = Keysyms.F2; break;
      case KeyEvent.VK_F3:           keysym = Keysyms.F3; break;
      case KeyEvent.VK_F4:           keysym = Keysyms.F4; break;
      case KeyEvent.VK_F5:           keysym = Keysyms.F5; break;
      case KeyEvent.VK_F6:           keysym = Keysyms.F6; break;
      case KeyEvent.VK_F7:           keysym = Keysyms.F7; break;
      case KeyEvent.VK_F8:           keysym = Keysyms.F8; break;
      case KeyEvent.VK_F9:           keysym = Keysyms.F9; break;
      case KeyEvent.VK_F10:          keysym = Keysyms.F10; break;
      case KeyEvent.VK_F11:          keysym = Keysyms.F11; break;
      case KeyEvent.VK_F12:          keysym = Keysyms.F12; break;
      case KeyEvent.VK_F13:          keysym = Keysyms.F13; break;
      case KeyEvent.VK_F14:          keysym = Keysyms.F14; break;
      case KeyEvent.VK_F15:          keysym = Keysyms.F15; break;
      case KeyEvent.VK_F16:          keysym = Keysyms.F16; break;
      case KeyEvent.VK_F17:          keysym = Keysyms.F17; break;
      case KeyEvent.VK_F18:          keysym = Keysyms.F18; break;
      case KeyEvent.VK_F19:          keysym = Keysyms.F19; break;
      case KeyEvent.VK_F20:          keysym = Keysyms.F20; break;
      case KeyEvent.VK_F21:          keysym = Keysyms.F21; break;
      case KeyEvent.VK_F22:          keysym = Keysyms.F22; break;
      case KeyEvent.VK_F23:          keysym = Keysyms.F23; break;
      case KeyEvent.VK_F24:          keysym = Keysyms.F24; break;
      case KeyEvent.VK_PRINTSCREEN:  keysym = Keysyms.Print; break;
      case KeyEvent.VK_SCROLL_LOCK:  keysym = Keysyms.Scroll_Lock; break;
      case KeyEvent.VK_CAPS_LOCK:    keysym = Keysyms.Caps_Lock; break;
      case KeyEvent.VK_NUM_LOCK:     keysym = Keysyms.Num_Lock; break;
      case KeyEvent.VK_PAUSE:
        if (ev.isControlDown())
          keysym = Keysyms.Break;
        else
          keysym = Keysyms.Pause;
        break;
      case KeyEvent.VK_INSERT:
        if (location == KeyEvent.KEY_LOCATION_NUMPAD)
          keysym = Keysyms.KP_Insert;
        else
          keysym = Keysyms.Insert;  break;
      // case KeyEvent.VK_FINAL:     keysym = Keysyms.?; break;
      // case KeyEvent.VK_CONVERT:     keysym = Keysyms.?; break;
      // case KeyEvent.VK_NONCONVERT:     keysym = Keysyms.?; break;
      // case KeyEvent.VK_ACCEPT:     keysym = Keysyms.?; break;
      // case KeyEvent.VK_MODECHANGE:     keysym = Keysyms.Mode_switch?; break;
      // case KeyEvent.VK_KANA:     keysym = Keysyms.Kana_shift?; break;
      case KeyEvent.VK_KANJI:     keysym = Keysyms.Kanji; break;
      // case KeyEvent.VK_ALPHANUMERIC:     keysym = Keysyms.Eisu_Shift?; break;
      case KeyEvent.VK_KATAKANA:     keysym = Keysyms.Katakana; break;
      case KeyEvent.VK_HIRAGANA:     keysym = Keysyms.Hiragana; break;
      // case KeyEvent.VK_FULL_WIDTH:     keysym = Keysyms.?; break;
      // case KeyEvent.VK_HALF_WIDTH:     keysym = Keysyms.?; break;
      // case KeyEvent.VK_ROMAN_CHARACTERS:     keysym = Keysyms.?; break;
      // case KeyEvent.VK_ALL_CANDIDATES:     keysym = Keysyms.MultipleCandidate?; break;
      case KeyEvent.VK_PREVIOUS_CANDIDATE:     keysym = Keysyms.PreviousCandidate; break;
      case KeyEvent.VK_CODE_INPUT:     keysym = Keysyms.Codeinput; break;
      // case KeyEvent.VK_JAPANESE_KATAKANA:     keysym = Keysyms.?; break;
      // case KeyEvent.VK_JAPANESE_HIRAGANA:     keysym = Keysyms.?; break;
      case KeyEvent.VK_JAPANESE_ROMAN:     keysym = Keysyms.Romaji; break;
      case KeyEvent.VK_KANA_LOCK:     keysym = Keysyms.Kana_Lock; break;
      // case KeyEvent.VK_INPUT_METHOD_ON_OFF:     keysym = Keysyms.?; break;

      case KeyEvent.VK_AGAIN:     keysym = Keysyms.Redo; break;
      case KeyEvent.VK_UNDO:     keysym = Keysyms.Undo; break;
      // case KeyEvent.VK_COPY:     keysym = Keysyms.?; break;
      // case KeyEvent.VK_PASTE:     keysym = Keysyms.?; break;
      // case KeyEvent.VK_CUT:     keysym = Keysyms.?; break;
      case KeyEvent.VK_FIND:     keysym = Keysyms.Find; break;
      // case KeyEvent.VK_PROPS:     keysym = Keysyms.?; break;
      case KeyEvent.VK_STOP:     keysym = Keysyms.Cancel; break;
      case KeyEvent.VK_HELP:         keysym = Keysyms.Help; break;
      case KeyEvent.VK_WINDOWS:
        if (down)
          modifiers |= SUPER_MASK;
        else
          modifiers &= ~SUPER_MASK;
        keysym = Keysyms.Super_L; break;
      case KeyEvent.VK_CONTEXT_MENU: keysym = Keysyms.Menu; break;
      default: return;
      }
    }

    if (keysym > 0) {
      String fmt = ev.paramString().replaceAll("%","%%");
      vlog.debug(String.format(fmt.replaceAll(",","%n       ")));

      writeKeyEvent(keysym, down);
    }
  }

  public void writePointerEvent(MouseEvent ev) {
    if (state() != RFBSTATE_NORMAL || shuttingDown)
      return;

    switch (ev.getID()) {
    case MouseEvent.MOUSE_PRESSED:
      buttonMask = 1;
      if ((ev.getModifiers() & KeyEvent.ALT_MASK) != 0) buttonMask = 2;
      if ((ev.getModifiers() & KeyEvent.META_MASK) != 0) buttonMask = 4;
      break;
    case MouseEvent.MOUSE_RELEASED:
      buttonMask = 0;
      break;
    }

    if (cp.width != desktop.scaledWidth ||
        cp.height != desktop.scaledHeight) {
      int sx = (desktop.scaleWidthRatio == 1.00) ?
        ev.getX() : (int)Math.floor(ev.getX() / desktop.scaleWidthRatio);
      int sy = (desktop.scaleHeightRatio == 1.00) ?
        ev.getY() : (int)Math.floor(ev.getY() / desktop.scaleHeightRatio);
      ev.translatePoint(sx - ev.getX(), sy - ev.getY());
    }

    writer().writePointerEvent(new Point(ev.getX(), ev.getY()), buttonMask);
  }

  public void writeWheelEvent(MouseWheelEvent ev) {
    if (state() != RFBSTATE_NORMAL || shuttingDown)
      return;
    int x, y;
    int clicks = ev.getWheelRotation();
    if (clicks < 0) {
      buttonMask = 8;
    } else {
      buttonMask = 16;
    }
    for (int i = 0; i < Math.abs(clicks); i++) {
      x = ev.getX();
      y = ev.getY();
      writer().writePointerEvent(new Point(x, y), buttonMask);
      buttonMask = 0;
      writer().writePointerEvent(new Point(x, y), buttonMask);
    }

  }

  synchronized void releaseModifiers() {
    if ((modifiers & Event.SHIFT_MASK) == Event.SHIFT_MASK)
      writeKeyEvent(Keysyms.Shift_R, false);
    if (((modifiers>>KEY_LOC_SHIFT_L) & Event.SHIFT_MASK) == Event.SHIFT_MASK)
      writeKeyEvent(Keysyms.Shift_L, false);
    if ((modifiers & Event.CTRL_MASK) == Event.CTRL_MASK)
      writeKeyEvent(Keysyms.Control_R, false);
    if (((modifiers>>KEY_LOC_SHIFT_L) & Event.CTRL_MASK) == Event.CTRL_MASK)
      writeKeyEvent(Keysyms.Control_L, false);
    if ((modifiers & Event.ALT_MASK) == Event.ALT_MASK)
      writeKeyEvent(Keysyms.Alt_R, false);
    if (((modifiers>>KEY_LOC_SHIFT_L) & Event.ALT_MASK) == Event.ALT_MASK)
      writeKeyEvent(Keysyms.Alt_L, false);
    if ((modifiers & Event.META_MASK) == Event.META_MASK)
      writeKeyEvent(Keysyms.Meta_R, false);
    if (((modifiers>>KEY_LOC_SHIFT_L) & Event.META_MASK) == Event.META_MASK)
      writeKeyEvent(Keysyms.Meta_L, false);
    if ((modifiers & SUPER_MASK) == SUPER_MASK)
      writeKeyEvent(Keysyms.Super_L, false);
    modifiers = 0;
  }


  ////////////////////////////////////////////////////////////////////
  // The following methods are called from both RFB and GUI threads

  // checkEncodings() sends a setEncodings message if one is needed.
  private void checkEncodings() {
    if (encodingChange && (writer() != null)) {
      vlog.info("Requesting " + Encodings.encodingName(currentEncoding) +
        " encoding");
      writer().writeSetEncodings(currentEncoding, true);
      encodingChange = false;
    }
  }

  // the following never change so need no synchronization:


  // viewer object is only ever accessed by the GUI thread so needs no
  // synchronization (except for one test in DesktopWindow - see comment
  // there).
  VncViewer viewer;

  // access to desktop by different threads is specified in DesktopWindow

  // the following need no synchronization:

  public static UserPasswdGetter upg;
  public UserMsgBox msg;

  // shuttingDown is set by the GUI thread and only ever tested by the RFB
  // thread after the window has been destroyed.
  boolean shuttingDown = false;

  // reading and writing int and boolean is atomic in java, so no
  // synchronization of the following flags is needed:
  
  int lowColourLevel;


  // All menu, options, about and info stuff is done in the GUI thread (apart
  // from when constructed).
  F8Menu menu;
  OptionsDialog options;

  // clipboard sync issues?
  ClipboardDialog clipboardDialog;

  // the following are only ever accessed by the GUI thread:
  int buttonMask;

  private String serverHost;
  private int serverPort;
  private Socket sock;

  protected DesktopWindow desktop;

  // FIXME: should be private
  public PixelFormat serverPF;
  private PixelFormat fullColourPF;

  private boolean pendingPFChange;
  private PixelFormat pendingPF;

  private int currentEncoding, lastServerEncoding;

  private boolean formatChange;
  private boolean encodingChange;

  private boolean firstUpdate;
  private boolean pendingUpdate;
  private boolean continuousUpdates;

  private boolean forceNonincremental;

  private boolean supportsSyncFence;

  int modifiers;
  public int menuKeyCode;
  Viewport viewport;
  private boolean fullColour;
  private boolean autoSelect;
  boolean fullScreen;
  
  static LogWriter vlog = new LogWriter("CConn");
}
