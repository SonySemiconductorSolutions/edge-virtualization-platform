/*
 * SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* backend.i */
%module _backend
%{
/* Includes the header in the wrapper code */
#include "../../external/include/evp/sdk.h"

%}

%ignore EVP_blobGetUploadURL(struct EVP_client *h, const char *storageName,
				const char *remoteName, EVP_BLOB_CALLBACK cb,
				void *userData);

/* Parse the header file to generate wrappers */
%include "../../external/include/evp/sdk_types.h"
%include "../../external/include/evp/sdk_base.h"
%include "../../external/include/evp/sdk_blob.h"

%inline %{
/* This function matches the prototype of a normal C callback
   function for our widget. However, the clientdata pointer
   actually refers to a Python callable object. */


/* Module instance Configuration */

static void PythonConfigCallback(const char *topic, const void *config, size_t configlen, void *userData)
{
   PyObject *func, *arglist;
   func = (PyObject *) userData;
   arglist = Py_BuildValue("(sO)", topic, PyUnicode_FromStringAndSize(config, configlen));
   PyObject *ret = PyObject_Call(func, arglist, NULL);
   if (!ret) {
      // Handle any Python exceptions raised during the callback
      PyErr_Print();
      PyErr_Clear();
   }
   Py_DECREF(arglist);
   Py_DECREF(ret);
}

static EVP_RESULT PyEVP_setConfigurationCallback(struct EVP_client *h, PyObject *PyHandler) {
	EVP_RESULT ret = EVP_setConfigurationCallback(h, PythonConfigCallback, (void *) PyHandler);
   if (ret == EVP_OK) {
	   Py_INCREF(PyHandler);
   }
	return ret;
}

/* Module instance State */

static void PythonReasonCallback(int reason, void *userData)
{
   PyObject *func, *arglist;
   func = (PyObject *) userData;
   arglist = Py_BuildValue("(i)", reason);
   PyObject *ret = PyObject_Call(func, arglist, NULL);
   if (!ret) {
      // Handle any Python exceptions raised during the callback
      PyErr_Print();
      PyErr_Clear();
   }
   Py_DECREF(arglist);
   Py_DECREF(func);
   Py_DECREF(ret);
}

static EVP_RESULT PyEVP_sendState(struct EVP_client *h, char *topic, char *value, int len, PyObject *PyHandler) {
   EVP_RESULT ret = EVP_sendState(h, topic, value, len, (EVP_STATE_CALLBACK)PythonReasonCallback, (void *) PyHandler);
   if (ret == EVP_OK) {
	   Py_INCREF(PyHandler);
   }
	return ret;
}

struct TelemetryCallbackData {
   PyObject *PyHandler;
   struct EVP_telemetry_entry *entries;
   Py_ssize_t size;
};

/* Telemetry */

static void TelemetryCallbackData_free(struct TelemetryCallbackData *data) {
   for (Py_ssize_t i = 0; i < data->size; i++) {
      Py_DECREF(data->entries[i].key);
      Py_DECREF(data->entries[i].value);
   }
   free(data->entries);
   free(data);
}

static void PythonTelemetryCallback(int reason, void *userData)
{
   PyObject *func, *arglist;
   struct TelemetryCallbackData *data = userData;

   func = (PyObject *) data->PyHandler;
   arglist = Py_BuildValue("(i)", reason);
   PyObject *ret = PyObject_Call(func, arglist, NULL);
   if (!ret) {
      // Handle any Python exceptions raised during the callback
      PyErr_Print();
      PyErr_Clear();
   }
   Py_DECREF(arglist);
   Py_DECREF(func);
   Py_DECREF(ret);

   TelemetryCallbackData_free(data);
}

static EVP_RESULT PyEVP_sendTelemetry(struct EVP_client *h, PyObject *Telemetries, PyObject *PyHandler) {
   EVP_RESULT ret;

   if (!PyList_Check(Telemetries)) {
         PyErr_SetString(PyExc_RuntimeError, "Telemetries must be a list of 2-tuples");
         return EVP_INVAL;
   }

   Py_ssize_t size = PyList_Size(Telemetries);

   struct TelemetryCallbackData *data = calloc(1, sizeof(struct TelemetryCallbackData));

   if (!data) {
      PyErr_NoMemory();
      return EVP_NOMEM;
   }

   struct EVP_telemetry_entry *entries = calloc(sizeof(struct EVP_telemetry_entry), size);

   if (!entries) {
      PyErr_NoMemory();
      free(data);
      return EVP_NOMEM;
   }

   /* validate */

   for (Py_ssize_t i = 0; i < size; i++) {
      PyObject *item = PyList_GetItem(Telemetries, i);
      if (!PyTuple_Check(item)) {
         free(entries);
         free(data);
         PyErr_SetString(PyExc_RuntimeError, "Each item should be a 2-tuple");
         return EVP_INVAL;
      }

      PyObject *key = PyTuple_GetItem(item, 0);
      PyObject *value = PyTuple_GetItem(item, 1);

      if (!PyUnicode_Check(key)) {
         free(entries);
         free(data);
         PyErr_SetString(PyExc_RuntimeError, "First element of tuple needs to be string");
         return EVP_INVAL;
      }
      if (!PyUnicode_Check(value)) {
         free(entries);
         free(data);
         PyErr_SetString(PyExc_RuntimeError, "Second element of tuple needs to be string");
         return EVP_INVAL;
      }

   }

   /* convert */

   for (Py_ssize_t i = 0; i < size; i++) {
      PyObject *item = PyList_GetItem(Telemetries, i);

      PyObject *key = PyTuple_GetItem(item, 0);
      PyObject *value = PyTuple_GetItem(item, 1);

      entries[i] = (struct EVP_telemetry_entry){
         .key = PyUnicode_AsUTF8(key),
         .value = PyUnicode_AsUTF8(value),
      };

	   Py_INCREF(key);
	   Py_INCREF(value);
   }

   *data = (struct TelemetryCallbackData){
      .PyHandler = PyHandler,
      .entries = entries,
      .size = size,
   };

   ret = EVP_sendTelemetry(h, entries, size, (EVP_TELEMETRY_CALLBACK)PythonTelemetryCallback, data);

   if (ret == EVP_OK) {
	   Py_INCREF(PyHandler);
   }
   else {
      TelemetryCallbackData_free(data);
   }

	return ret;
}

/* Module Direct Command (Request)*/

static void PythonRpcRequestCallback(unsigned long id, const char *methodName,
					 const char *params, void *userData) {
   PyObject *func, *arglist;

   func = (PyObject *) userData;
   arglist = Py_BuildValue("(lss)", id, methodName, params);
   PyObject *ret = PyObject_Call(func, arglist, NULL);
   if (!ret) {
      // Handle any Python exceptions raised during the callback
      PyErr_Print();
      PyErr_Clear();
   }
   Py_DECREF(arglist);
   Py_DECREF(ret);
}

EVP_RESULT PyEVP_setRpcCallback(struct EVP_client *h, PyObject *PyHandler) {
   EVP_RESULT ret = EVP_setRpcCallback(h, PythonRpcRequestCallback, (void *) PyHandler);
   if (ret == EVP_OK) {
	   Py_INCREF(PyHandler);
   }
	return ret;
}

/* Module Direct Command (Response) */

EVP_RESULT PyEVP_sendRpcResponse(struct EVP_client *h, unsigned long id,
			       const char *response,
			       EVP_RPC_RESPONSE_STATUS status,
			       PyObject *PyHandler) {

   EVP_RESULT ret = EVP_sendRpcResponse(h, id, response, status, (EVP_RPC_RESPONSE_CALLBACK)PythonReasonCallback, (void *) PyHandler);
   if (ret == EVP_OK) {
	   Py_INCREF(PyHandler);
   }
	return ret;
}


static EVP_RESULT PyEVP_processEvent(struct EVP_client *h, int timeout)
{
   int ret = EVP_processEvent(h, timeout);

   if (PyErr_Occurred()) {
      // Handle any Python exceptions raised during the callback
      PyErr_Print();
      PyErr_Clear();
      return EVP_ERROR;
   }

   return ret;
}

%}
