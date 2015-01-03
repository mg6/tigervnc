/* Copyright (C) 2002-2005 RealVNC Ltd.  All Rights Reserved.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
 * USA.
 */
/*  This is the xf86 module code for the vnc extension.
 */

#ifdef HAVE_DIX_CONFIG_H
#include <dix-config.h>
#endif

#include <rfb/Configuration.h>
#include <rfb/Logger_stdio.h>
#include <rfb/LogWriter.h>
#include <rfb/ScreenSet.h>
#include <rfb/screenTypes.h>

#include "xorg-version.h"

extern "C" {
#define class c_class
#define private c_private
#define bool c_bool
#define new c_new
#include "xf86.h"
#include "xf86Module.h"
#ifdef RANDR
#include "randrstr.h"
#endif /* RANDR */
#undef class
#undef private
#undef bool
#undef new

using namespace rfb;

extern void vncExtensionInit();
static void vncExtensionInitWithParams(INITARGS);

char *listenaddr = NULL;

static MODULESETUPPROTO(vncSetup);

ExtensionModule vncExt =
{
    vncExtensionInitWithParams,
    "VNC",
#if XORG < 112
    NULL,
    NULL,
#endif
    NULL
};

static XF86ModuleVersionInfo vncVersRec =
{
    "vnc",
    "Constantin Kaplinsky",
    MODINFOSTRING1,
    MODINFOSTRING2,
    XORG_VERSION_CURRENT,
    1, 0, 0,
    ABI_CLASS_EXTENSION,         /* needs the server extension ABI */
    ABI_EXTENSION_VERSION,
    MOD_CLASS_EXTENSION,
    {0,0,0,0}
};

_X_EXPORT XF86ModuleData vncModuleData = { &vncVersRec, vncSetup, NULL };

static void *
vncSetup(void * module, void * opts, int *errmaj, int *errmin) {
#if XORG >= 116
    LoadExtensionList(&vncExt, 1, FALSE);
#else
    LoadExtension(&vncExt, FALSE);
#endif
    /* Need a non-NULL return value to indicate success */
    return (void *)1;
}

static void vncExtensionInitWithParams(INITARGS)
{
  static char once = 0;

  if (!once) {
    once++;
    rfb::initStdIOLoggers();
    rfb::LogWriter::setLogParams("*:stderr:30");
    rfb::Configuration::enableServerParams();

    for (int scr = 0; scr < screenInfo.numScreens; scr++) {
      ScrnInfoPtr pScrn = xf86Screens[scr];

      for (ParameterIterator i; i.param; i.next()) {
        const char *val;
#if XORG < 112
        val = xf86FindOptionValue(pScrn->options, i.param->getName());
#else
        val = xf86FindOptionValue((XF86OptionPtr)pScrn->options, i.param->getName());
#endif
        if (val)
          i.param->setParam(val);
      }
    }
  }

  vncExtensionInit();
}
}

RRModePtr vncRandRModeGet(int width, int height)
{
    return NULL;
}

RROutputPtr vncRandROutputCreate(ScreenPtr pScreen)
{
    return NULL;
}
