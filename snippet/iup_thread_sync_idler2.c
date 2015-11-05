
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <pthread.h>

#include "iup.h"

#define TGUI_PRGRS_TUNING	0
#define TGUI_PRGRS_SCANNING	1
#define TGUI_PRGRS_INGROUP	2

#define TGUI_LBL_TUNE_ALL	0
#define TGUI_LBL_TUNE_FAIL	1
#define TGUI_LBL_SCAN_ALL	2
#define TGUI_LBL_SCAN_FAIL	3
#define TGUI_LBL_SCAN_NOW	4

typedef	struct	{
	char	inst_id[64]; 	/* instant identity */

	Ihandle	*dlg_main;

	Ihandle	*tune_label_total;
	Ihandle	*tune_label_fail;
	Ihandle	*tune_progress;

	Ihandle	*scan_label_total;
	Ihandle	*scan_label_fail;
	Ihandle	*scan_progress;
	Ihandle	*scan_label_current;
	Ihandle	*cur_progress;
} TuneGUI;

TuneGUI *tuner_gui_init(int *argcs, char ***argvs);
void *tuner_gui_run(void *arg);
int tuner_gui_close(TuneGUI *gui);
int tuner_gui_progress(TuneGUI *gui, int which, int val, int max);
int tuner_gui_status(TuneGUI *gui, int which, int val);


#define TGOBJ_MAIN	"TUNERGUIOBJ"

	TuneGUI	*gui;
static int	evt_update;
static void *task_command(void *arg);

int tuner_idle(void)
{
	static	int	last_update;

	if (evt_update != last_update) {
		last_update = evt_update;

		tuner_gui_progress(gui, TGUI_PRGRS_TUNING, evt_update, 0);
		tuner_gui_progress(gui, TGUI_PRGRS_SCANNING, evt_update, 0);
		tuner_gui_progress(gui, TGUI_PRGRS_INGROUP, evt_update, 0);
		tuner_gui_status(gui, TGUI_LBL_TUNE_ALL, evt_update);
		tuner_gui_status(gui, TGUI_LBL_TUNE_FAIL, evt_update + 100);
		tuner_gui_status(gui, TGUI_LBL_SCAN_ALL, evt_update + 1000);
		tuner_gui_status(gui, TGUI_LBL_SCAN_FAIL, evt_update + 10000);
		tuner_gui_status(gui, TGUI_LBL_SCAN_NOW, evt_update + 100000);
	}
	return 1;
}

TuneGUI *tuner_gui_init(int *argcs, char ***argvs)
{

	IupOpen(argcs, argvs);

	IupSetGlobal("SINGLEINSTANCE", "IQTuner");
	if (!IupGetGlobal("SINGLEINSTANCE")) {
		IupClose();
		return NULL;
	}

	//iupdrvSetIdleFunction((Icallback)tuner_idle);
	IupSetFunction("IDLE_ACTION", (Icallback)tuner_idle);

	if ((gui = (TuneGUI*)malloc(sizeof(TuneGUI))) == NULL) {
		return NULL;
	}

	/* initialize GUI structure with parameters from command line */
	sprintf(gui->inst_id, "IQTUNER_%p", gui);
	return gui;
}

void *tuner_gui_run(void *arg)
{
	TuneGUI	*gui = (TuneGUI *)arg;
	Ihandle	*vbox_tune, *vbox_scan, *vbox_dialog;
	Ihandle	*frame_tune, *frame_scan;
	pthread_t	task_cmd;

	gui->tune_label_total = IupText(NULL);
	IupSetAttribute(gui->tune_label_total, "READONLY", "YES");
	IupSetAttribute(gui->tune_label_total, "BORDER", "NO");
	IupSetAttribute(gui->tune_label_total, "BGCOLOR", "DLGBGCOLOR");
	IupSetAttribute(gui->tune_label_total, "CANFOCUS", "NO");
	IupSetAttribute(gui->tune_label_total, "SIZE", "120");

	tuner_gui_status(gui, TGUI_LBL_TUNE_ALL, 0);
	gui->tune_label_fail  = IupLabel("Failure of Tuning: 123456789");
	IupSetAttribute(gui->tune_label_fail, "SIZE", "120");
	tuner_gui_status(gui, TGUI_LBL_TUNE_FAIL, 0);
	gui->tune_progress = IupProgressBar();
	IupSetAttribute(gui->tune_progress, "EXPAND", "HORIZONTAL");
	IupSetAttribute(gui->tune_progress, "SIZE", "x10");
	IupSetAttribute(gui->tune_progress, "DASHED", "YES");
	IupSetInt(gui->tune_progress, "MIN", 1);
	IupSetInt(gui->tune_progress, "MAX", 728);
	vbox_tune = IupVbox(gui->tune_label_total, gui->tune_label_fail, 
			gui->tune_progress, NULL);
	IupSetAttribute(vbox_tune, "NGAP", "8");
	IupSetAttribute(vbox_tune, "NMARGIN", "8x8");

	frame_tune = IupFrame(vbox_tune);
	IupSetAttribute(frame_tune, "TITLE", " Frequency Tuning ");

	gui->scan_label_total = IupLabel("Total Scanned: 123456789");
	tuner_gui_status(gui, TGUI_LBL_SCAN_ALL, 0);
	gui->scan_label_fail  = IupLabel("Failure of Scanning: 123456789");
	tuner_gui_status(gui, TGUI_LBL_SCAN_FAIL, 0);
	gui->scan_progress = IupProgressBar();
	IupSetAttribute(gui->scan_progress, "EXPAND", "HORIZONTAL");
	IupSetAttribute(gui->scan_progress, "SIZE", "x10");
	IupSetAttribute(gui->scan_progress, "DASHED", "YES");
	IupSetInt(gui->scan_progress, "MIN", 0);
	IupSetInt(gui->scan_progress, "MAX", 227);

	gui->scan_label_current = IupLabel("Current Frequency: 123456789");
	tuner_gui_status(gui, TGUI_LBL_SCAN_NOW, 0);
	gui->cur_progress = IupProgressBar();
	IupSetAttribute(gui->cur_progress, "EXPAND", "HORIZONTAL");
	IupSetAttribute(gui->cur_progress, "SIZE", "x10");
	IupSetAttribute(gui->cur_progress, "DASHED", "YES");
	vbox_scan = IupVbox(gui->scan_label_total, gui->scan_label_fail,
			gui->scan_progress, IupFill(), gui->scan_label_current,
			gui->cur_progress, NULL);
	IupSetAttribute(vbox_scan, "NGAP", "8");
	IupSetAttribute(vbox_scan, "NMARGIN", "8x8");

	frame_scan = IupFrame(vbox_scan);
	IupSetAttribute(frame_scan, "TITLE", " Frequency Scanning ");

	vbox_dialog = IupVbox(frame_tune, frame_scan, NULL);
	IupSetAttribute(vbox_dialog, "NGAP", "8");
	IupSetAttribute(vbox_dialog, "NMARGIN", "16x16");

	gui->dlg_main = IupDialog(vbox_dialog);
	IupSetAttribute(gui->dlg_main, "TITLE", "IQTuner");
	IupSetAttribute(gui->dlg_main, TGOBJ_MAIN, (char*) gui);
	IupSetAttribute(gui->dlg_main, "RASTERSIZE", "500x400");
	IupSetHandle(gui->inst_id, gui->dlg_main);

	tuner_gui_progress(gui, TGUI_PRGRS_TUNING, 0, 100);
	tuner_gui_progress(gui, TGUI_PRGRS_SCANNING, 0, 100);
	tuner_gui_progress(gui, TGUI_PRGRS_INGROUP, 0, 100);
	
	IupShow(gui->dlg_main);

	pthread_create(&task_cmd, NULL, task_command, gui);
	IupMainLoop();
	pthread_cancel(task_cmd);
	pthread_join(task_cmd, NULL);

	return NULL;
}

int tuner_gui_close(TuneGUI *gui)
{
	if (gui) {
		IupDestroy(gui->dlg_main);
		IupClose();
		free(gui);
	}
	return 0;
}

int tuner_gui_progress(TuneGUI *gui, int which, int val, int max)
{
	switch (which) {
	case TGUI_PRGRS_TUNING:
		if (max == 0) {
			IupSetInt(gui->tune_progress, "VALUE", val);
		} else {
			IupSetInt(gui->tune_progress, "MIN", val);
			IupSetInt(gui->tune_progress, "MAX", max);
		}
		break;
	case TGUI_PRGRS_SCANNING:
		if (max == 0) {
			IupSetInt(gui->scan_progress, "VALUE", val);
		} else {
			IupSetInt(gui->scan_progress, "MIN", val);
			IupSetInt(gui->scan_progress, "MAX", max);
		}
		break;
	case TGUI_PRGRS_INGROUP:
		if (max == 0) {
			IupSetInt(gui->cur_progress, "VALUE", val);
		} else {
			IupSetInt(gui->cur_progress, "MIN", val);
			IupSetInt(gui->cur_progress, "MAX", max);
		}
		break;
	}

	return 0;
}

int tuner_gui_status(TuneGUI *gui, int which, int val)
{
	static	char	tune_all[64];
	static	char	tune_fail[64];
	static	char	scan_all[64];
	static	char	scan_fail[64];
	static	char	scan_now[64];

	switch (which) {
	case TGUI_LBL_TUNE_ALL:
		sprintf(tune_all, "Frequency Tuned: %d", val);
		IupSetAttribute(gui->tune_label_total, "VALUE", tune_all);
		break;
	case TGUI_LBL_TUNE_FAIL:
		sprintf(tune_fail, "Failure of Tuning: %d", val);
		//puts(tune_fail);
		IupSetAttribute(gui->tune_label_fail, "TITLE", tune_fail);
		//IupUpdate(gui->tune_label_fail);
		break;
	case TGUI_LBL_SCAN_ALL:
		sprintf(scan_all, "Total Scanned: %d", val);
		//puts(scan_all);
		IupSetAttribute(gui->scan_label_total, "TITLE", scan_all);
		break;
	case TGUI_LBL_SCAN_FAIL:
		sprintf(scan_fail, "Failure of Scanning: %d", val);
		//puts(scan_fail);
		IupSetAttribute(gui->scan_label_fail, "TITLE", scan_fail);
		break;
	case TGUI_LBL_SCAN_NOW:
		sprintf(scan_now, "Current Frequency: %d", val);
		//puts(scan_now);
		IupSetAttribute(gui->scan_label_current, "TITLE", scan_now);
		break;
	}
	return 0;
}


/* g++ -Wall -fexceptions -g -DGUI_LOCAL_TEST -I./external/iup/include `pkg-config gtk+-2.0 --cflags` -L./external/iup/lib/Linux311_64  -o iqtuner  iqiup.cpp -lpthread -liup `pkg-config gtk+-2.0 --libs` -lX11
 */
static void *task_command(void *arg)
{
	TuneGUI	*gui = (TuneGUI *)arg;

	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

	for (evt_update = 0; evt_update <= 100; evt_update++) {
		sleep(1);
	}
	return NULL;
}

int main(int argc, char **argv)
{
	pthread_t	task_cmd, task_gui;
	TuneGUI		*gui;

	gui = tuner_gui_init(&argc, &argv);
	pthread_create(&task_gui, NULL, tuner_gui_run, gui);

	pthread_join(task_gui, NULL);
	tuner_gui_close(gui);
	return 0;
}

