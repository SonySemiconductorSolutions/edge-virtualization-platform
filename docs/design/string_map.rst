.. SPDX-FileCopyrightText: 2023-2024 Sony Semiconductor Solutions Corporation
..
.. SPDX-License-Identifier: Apache-2.0

String map
**********

String maps allow users
to store elements based on a key-value pair.
Whereas the value is an opaque pointer,
keys are always defined as strings.
This allows the use
of a string hash function,
such as `DJB2`_.
String maps are hash tables defined
by the ``struct string_map`` data type.

The following functions can be used with a string map:

	- ``string_map_alloc``: Allocate a new ``struct string_map`` instance.
	  ``n`` determines
	  the behavior of the map,
	  where a larger value will make the lookups faster,
	  but will require more memory
	  even with an empty mapping.
	  ``free_fn`` defines
	  a user-provided callback
	  that will free every value contained within the map.
	  ``free_fn`` can be a null pointer
	  if values inside the map
	  must not be released
	  when calling ``string_map_dealloc``.
	- ``string_map_insert``: Add an item into a string map.
	  Returns zero on success;
	  non-zero otherwise.
	- ``string_map_lookup``: Finds an item inside the table
	  with a given key.
	  Returns a pointer to the item when successful;
	  ``NULL`` otherwise.
	- ``string_map_forall``: Iterate through all items inside the table
	  and call a user-defined callback
	  with an optional opaque pointer.
	  Returns zero on success;
	  non-zero otherwise.
	  The user-defined callback
	  must return
	  zero on failure;
	  when successful,
	  it must return a negative number
	  if the item must be removed,
	  or a positive number otherwise.

-----------------

.. _DJB2: http://www.cse.yorku.ca/~oz/hash.html
