/* hacktv - Analogue video transmitter for the HackRF                    */
/*=======================================================================*/
/* Copyright 2017 Philip Heron <phil@sanslogic.co.uk>                    */
/*                                                                       */
/* This program is free software: you can redistribute it and/or modify  */
/* it under the terms of the GNU General Public License as published by  */
/* the Free Software Foundation, either version 3 of the License, or     */
/* (at your option) any later version.                                   */
/*                                                                       */
/* This program is distributed in the hope that it will be useful,       */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of        */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         */
/* GNU General Public License for more details.                          */
/*                                                                       */
/* You should have received a copy of the GNU General Public License     */
/* along with this program.  If not, see <http://www.gnu.org/licenses/>. */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "DTAPI.h"
#include "hacktv.h"
#include "dektec.h"

/* buffer length in bytes - must be a multiple of 4 */
#define BUF_LEN (1024*1024)

typedef struct {
	
	/* Dektec device nodes */
	DtDevice dtDev;
	DtOutpChannel dtOutp;
	
	char txbuf[BUF_LEN];
	size_t txbufWrPtr = 0;

	uint64_t initialLoadTarget;
	uint64_t fifoLoad = 0;
	bool doneInitialLoad = false;
	
} dektec_t;

static int _rf_write(void *rf_private, int16_t *iq_data, size_t samples)
{
	dektec_t *rf = static_cast<dektec_t*>(rf_private);

	size_t samps = samples;
	int16_t *iqp = iq_data;

	while (samps > 0) {
		// work out how many samples we can store in the buffer
		size_t n = 
			samps < ((BUF_LEN - rf->txbufWrPtr) / 4) ?
				samps :
				((BUF_LEN - rf->txbufWrPtr) / 4);

		char *p = rf->txbuf;
		int16_t iv,qv;
		for (size_t i=0; i<n; i++) {
			iv = *(iqp++);
			qv = *(iqp++);

			iv /= 8;
			qv /= 8;

			// load samples into tx buffer
			rf->txbuf[rf->txbufWrPtr++] = iv & 0xff;
			rf->txbuf[rf->txbufWrPtr++] = iv >> 8;
			rf->txbuf[rf->txbufWrPtr++] = qv & 0xff;
			rf->txbuf[rf->txbufWrPtr++] = qv >> 8;
		}

		if (rf->txbufWrPtr == BUF_LEN) {
			// check for FIFO underrun (if initial load complete)
			if (rf->doneInitialLoad) {
				int fifoLoad;
				rf->dtOutp.GetFifoLoad(fifoLoad);
				if (fifoLoad == 0) {
					fprintf(stderr, "DECTEC TX: FIFO buffer underrun\n");
				} else if (fifoLoad < (BUF_LEN/2)) {
					fprintf(stderr, "DECTEC TX: FIFO buffer low! Only %d bytes in FIFO\n", fifoLoad);
				}
			}

			// transmit the buffer
			DTAPI_RESULT dr = rf->dtOutp.Write(rf->txbuf, rf->txbufWrPtr);
			if (dr != DTAPI_OK)
			{
				fprintf(stderr, "DEKTEC TX: Write failed: %s\n", DtapiResult2Str(dr));
				return(HACKTV_ERROR);
			}

			rf->txbufWrPtr = 0;
		}

		// update number of remaining samples
		samps -= n;
	}

	// Check if initial FIFO load is complete
	if (!rf->doneInitialLoad)
	{
		rf->fifoLoad += (samples*4);

		if (rf->fifoLoad >= rf->initialLoadTarget)
		{
			fprintf(stderr, "DEKTEC TX: Initial fifo load complete, starting transmission\n");
			// Start transmission
			DTAPI_RESULT dr = rf->dtOutp.SetTxControl(DTAPI_TXCTRL_SEND);
			if (dr != DTAPI_OK)
			{
				fprintf(stderr, "DEKTEC TX: SetTxControl failed: %s\n", DtapiResult2Str(dr));
				return(HACKTV_ERROR);
			}
			rf->doneInitialLoad = true;
		}		
	}

	return(HACKTV_OK);
}

static int _rf_close(void *rf_private)
{
	dektec_t *rf = static_cast<dektec_t*>(rf_private);

    // Detach from output channel and device
    rf->dtOutp.SetTxControl(DTAPI_TXCTRL_IDLE);
    rf->dtOutp.Detach(DTAPI_INSTANT_DETACH);
    rf->dtDev.Detach();

	delete rf;
	
	return(HACKTV_OK);
}


bool hasOutputPort(DtDevice &dtDev)
{
	DtHwFuncDesc HwFuncs[16];
	int  NumHwFuncs;
	DTAPI_RESULT dr;
	
	dr = dtDev.HwFuncScan(sizeof(HwFuncs)/sizeof(HwFuncs[0]), NumHwFuncs, HwFuncs);
	if (dr != DTAPI_OK) {
		return false;
	}
	
	for (int i=0; i<NumHwFuncs; i++)
	{
		if (((HwFuncs[i].m_Flags&DTAPI_CAP_OUTPUT) != 0) /*|| ((HwFuncs[i].m_Flags&DTAPI_CAP_IP) != 0)*/) {
			return true;
		}
	}
	return false;
}

int rf_dektec_open(hacktv_t *s, const char *device, unsigned int frequency_hz, unsigned int gain)
{
	dektec_t *rf;

	DTAPI_RESULT dr;
	
	// Check output type is 16-bit integer I-Q
	if(s->vid.conf.output_type != HACKTV_INT16_COMPLEX)
	{
		fprintf(stderr, "rf_dektec_open(): Unsupported mode output type for this device.\n");
		return(HACKTV_ERROR);
	}

	// Check frequency is set
	if(s->frequency == 0)
	{
		fprintf(stderr, "rf_dektec_open(): Output frequency is not set.\n");
		return(HACKTV_ERROR);
	}

	// Allocate the private structure
	try
	{
		rf = new dektec_t;
	}
	catch (const std::bad_alloc &e)
	{
		return(HACKTV_OUT_OF_MEMORY);
	}
	
	// Display the DTAPI version for convenience
	fprintf(stderr, "DEKTEC: DTAPI compile version: V%d.%d.%d.%d\n",
			DTAPI_VERSION_MAJOR, DTAPI_VERSION_MINOR, DTAPI_VERSION_BUGFIX, DTAPI_VERSION_BUILD);

	int  Maj=-1,Min=-1,BugFix=-1,Build=-1;
	DtapiGetVersion(Maj,Min,BugFix,Build);
	fprintf(stderr, "DEKTEC: DTAPI library version: V%d.%d.%d.%d\n",
			Maj, Min, BugFix, Build);

	// Check that the DTAPI header and library versions are compatible
	if ((DTAPI_VERSION_MAJOR != Maj) || (DTAPI_VERSION_MINOR != Min)) {
		fprintf(stderr, "FATAL: DTAPI headers and library are mismatched! Rebuild with correct headers.");
		return(HACKTV_ERROR);
	}


	//
	// TODO: FIXME: Parse "device" into either:
	//    serialnumber,port (devType will be -1, port may be -1 if unspecified)
	//    type,port (serialNumber will be -1, port may be -1 if unspecified)
	//
	// The trick is, a device type should be a maximum of 5 digits (99,999) in length
	// Serial numbers are a lot longer.
	//
	// For now we assume the device parameter is just the serial number
	//

	unsigned long long serialNumber = -1;
	int devType = -1;
	int port = -1;

	if (device != nullptr) {
		serialNumber = atoll(device);
	}

	// Try to attach to the output card with the given serial number, or default
	// to the first output card if a serial number isn't specified.
	if (serialNumber != -1) {
		dr = rf->dtDev.AttachToSerial(serialNumber);
		if (dr != DTAPI_OK) {
			fprintf(stderr, "DEKTEC: DtDevice.AttachToSerial(%llu) failed: %s\n",
					atoll(device), DtapiResult2Str(dr));
			return(HACKTV_ERROR);
		}
	}
	else
	{
		// No specific device identified, connect to the first one with an output port
		DtDeviceDesc DvcDescs[10];
		int NumDvcs;

		dr = DtapiDeviceScan(sizeof(DvcDescs)/sizeof(DvcDescs[0]), NumDvcs, DvcDescs);
		if (dr != DTAPI_OK) {
			fprintf(stderr, "DEKTEC: DtapiDeviceScan() failed: %s\n", DtapiResult2Str(dr));
			return(HACKTV_ERROR);
		}
	
		fprintf(stderr, "DEKTEC: DtapiDeviceScan() found %d devices\n", NumDvcs);
		
		bool FoundDvc = false;
		for (int i=0; i<NumDvcs; i++)
		{
			// Try to attach to the card by its serial number
			dr = rf->dtDev.AttachToSerial(DvcDescs[i].m_Serial);
			if (dr != DTAPI_OK) {
				fprintf(stderr, "DEKTEC: Failed to attach to Dektec card (type=%d, serial=%lld) failed: %s\n",
						DvcDescs[i].m_TypeNumber, DvcDescs[i].m_Serial, DtapiResult2Str(dr));
				return(HACKTV_ERROR);
			}

			// Make sure the card has output ports (otherwise it's useless to us)
			if (!hasOutputPort(rf->dtDev))
			{
				fprintf(stderr, "DEKTEC: Dektec card (type=%d, serial=%lld) has no outputs\n",
						DvcDescs[i].m_TypeNumber, DvcDescs[i].m_Serial);
				rf->dtDev.Detach();
				continue;
			}

			// Card is connected and has outputs, great!
			fprintf(stderr, "DEKTEC: Attached to Dektec type=%d card, s/n %lld\n",
					DvcDescs[i].m_TypeNumber, DvcDescs[i].m_Serial);
			FoundDvc = true;
			break;
		}

		if (!FoundDvc)
		{
			fprintf(stderr, "DEKTEC: Couldn't find any available Dektec devices with output ports\n");
			return(HACKTV_ERROR);
		}
	}


	// Conect to the Dektec port
    DtHwFuncDesc HwFuncs[16];
    int  NumHwFuncs;
    dr = rf->dtDev.HwFuncScan(sizeof(HwFuncs)/sizeof(HwFuncs[0]), NumHwFuncs, HwFuncs);
    if (dr != DTAPI_OK)
    {
		fprintf(stderr, "DEKTEC: HwFuncScan failed: %s\n", DtapiResult2Str(dr));
		return(HACKTV_ERROR);
	}

	if (port != -1)
	{
		// Port number has been specified -- check it and open it
		if ((port < 1) || (port > NumHwFuncs))
        {
			fprintf(stderr, "DEKTEC: Card has no port number %d\n", port);
			return(HACKTV_ERROR);
        }

        if ((HwFuncs[port-1].m_Flags & DTAPI_CAP_OUTPUT) != 0)
        {
            // User has explicitly selected a port, make sure it's configured as output.
            dr = rf->dtDev.SetIoConfig(port, DTAPI_IOCONFIG_IODIR, DTAPI_IOCONFIG_OUTPUT, DTAPI_IOCONFIG_OUTPUT);
            if (dr != DTAPI_OK)
			{
				fprintf(stderr, "DEKTEC: Failed to set I/O configuration: %s\n", DtapiResult2Str(dr));
				return(HACKTV_ERROR);
			}
        }
	}
	else
	{
		// Port number not specified, use the first compatible port
        for (int i=0; i<NumHwFuncs; i++)
        {
            if ((HwFuncs[i].m_Flags & DTAPI_CAP_OUTPUT) != 0) 
            {
                int Value = -1;
                dr = rf->dtDev.GetIoConfig(i+1, DTAPI_IOCONFIG_IODIR, Value);
				if (dr != DTAPI_OK)
				{
					fprintf(stderr, "DEKTEC: Failed to get I/O configuration: %s\n", DtapiResult2Str(dr));
					return(HACKTV_ERROR);
				}

                if (Value != DTAPI_IOCONFIG_OUTPUT)
				{
                    continue;
				}
            }
			else
			{
                continue;
			}

            // Check for a modulator port
			if ((HwFuncs[i].m_Flags & DTAPI_CAP_MOD) != 0)
            {
                port = i+1;
                break;
            }
        }

        if (port == -1)
		{
			fprintf(stderr, "DEKTEC: No suitable output ports\n");
			return(HACKTV_ERROR);	
		}
	}

	fprintf(stderr, "DEKTEC: Initialising output on modulator port %d\n", port);

/*
	// Enable double-buffered output mode
	dr = rf->dtDev.SetIoConfig(port, DTAPI_IOCONFIG_IODIR, DTAPI_IOCONFIG_OUTPUT, DTAPI_IOCONFIG_DBLBUF, port);
	if (dr != DTAPI_OK)
	{
		fprintf(stderr, "DEKTEC: Failed to enable double-buffering: %s\n", DtapiResult2Str(dr));
		return(HACKTV_ERROR);
	}
*/

	// Attach to the output channel
	dr = rf->dtOutp.AttachToPort(&rf->dtDev, port);
    if (dr == DTAPI_OK_FAILSAFE)
	{
		fprintf(stderr, "DEKTEC: Failsafe mode is not supported, but it is enabled. Use DtInfo to disable failsafe first.");
		return(HACKTV_ERROR);
	}
	else if (dr != DTAPI_OK)
	{
		fprintf(stderr, "DEKTEC: Failed to attach output channel to port %d: %s\n", port, DtapiResult2Str(dr));
		return(HACKTV_ERROR);
	}

    // Init channel to initial 'safe' state
    dr = rf->dtOutp.SetTxControl(DTAPI_TXCTRL_IDLE);  // Start in IDLE mode
    if (dr != DTAPI_OK)
	{
		fprintf(stderr, "DEKTEC: SetTxControl(IDLE) failed: %s\n", DtapiResult2Str(dr));
		return(HACKTV_ERROR);
	}

	// Get fifo size and calculate initial load
	int FifoSize;
	dr = rf->dtOutp.GetFifoSize(FifoSize);
    if (dr != DTAPI_OK)
	{
		fprintf(stderr, "DEKTEC: GetFifoSize failed: %s\n", DtapiResult2Str(dr));
		return(HACKTV_ERROR);
	}

	rf->initialLoadTarget = (FifoSize / 4) * 3;

	fprintf(stderr, "DEKTEC: FIFO size %d bytes -- aiming for an initial load of %d bytes\n", FifoSize, rf->initialLoadTarget);

	// Set transmit mode to raw and unstuffed
	dr = rf->dtOutp.SetTxMode(DTAPI_TXMODE_RAW, DTAPI_TXSTUFF_MODE_OFF);
    if (dr != DTAPI_OK)
	{
		fprintf(stderr, "DEKTEC: SetTxMode(DTAPI_TXMODE_RAW, DTAPI_TXSTUFF_MODE_OFF) failed: %s\n", DtapiResult2Str(dr));
		return(HACKTV_ERROR);
	}

	// Apply modulation settings
	dr = rf->dtOutp.SetRfControl(__int64(frequency_hz));
    if (dr != DTAPI_OK)
	{
		fprintf(stderr, "DEKTEC: SetRfControl(%u) failed: %s\n", frequency_hz, DtapiResult2Str(dr));
		return(HACKTV_ERROR);
	}

	fprintf(stderr, "DEKTEC: Output frequency = %u Hz (%0.3f MHz)\n", frequency_hz, frequency_hz / 1.0e6);
	fprintf(stderr, "DEKTEC: Sample rate = %d Hz (%0.3f MHz)\n", s->samplerate, s->samplerate / 1.0e6);

	// Set IQ direct mode
	dr = rf->dtOutp.SetModControl(
				DTAPI_MOD_IQDIRECT,			// Modulation mode: direct I-Q
				DTAPI_MOD_INTERPOL_QAM,		// Interpolation filter -- DTAPI_MOD_INTERPOL_RAW, DTAPI_MOD_INTERPOL_OFDM or DTAPI_MOD_INTERPOL_QAM.
											// OFDM and RAW don't seem to work for PAL (no audio). QAM is fine.
				s->samplerate,				// Sample rate
				DTAPI_MOD_ROLLOFF_NONE);
	if (dr != DTAPI_OK)
	{
		fprintf(stderr, "DEKTEC: Failed to set modulation parameters: %s\n", DtapiResult2Str(dr));
		return(HACKTV_ERROR);
	}

    // Set output level of main output (if supported)
    if ((rf->dtOutp.m_HwFuncDesc.m_Flags & DTAPI_CAP_ADJLVL) != 0)
    {
        // The SetOutputLevel method expects a level expressed in 0.1dBm units
        dr = rf->dtOutp.SetOutputLevel(gain * 10);
		if (dr != DTAPI_OK)
		{
			fprintf(stderr, "DEKTEC: Failed to set output level %d: %s\n", gain, DtapiResult2Str(dr));
			return(HACKTV_ERROR);
		}
		fprintf(stderr, "DEKTEC: Output level %d dB\n", gain);
    }
	else
	{
		fprintf(stderr, "DECTEC: Note: output level control is not supported on this hardware. Gain setting ignored.\n");
	}

    // Final initialisation
    dr = rf->dtOutp.ClearFifo();          // Clear FIFO (i.e. start with zero load)
	if (dr != DTAPI_OK)
	{
		fprintf(stderr, "DEKTEC: Failed to clear output FIFO: %s\n", DtapiResult2Str(dr));
		return(HACKTV_ERROR);
	}

	// Build initial fill in FIFO
    dr = rf->dtOutp.SetTxControl(DTAPI_TXCTRL_HOLD);
    if (dr != DTAPI_OK)
	{
		fprintf(stderr, "DEKTEC: SetTxControl(HOLD) failed: %s\n", DtapiResult2Str(dr));
		return(HACKTV_ERROR);
	}
	
	/* Register the callback functions */
	s->rf_private = rf;
	s->rf_write = _rf_write;
	s->rf_close = _rf_close;

	return(HACKTV_OK);
};
