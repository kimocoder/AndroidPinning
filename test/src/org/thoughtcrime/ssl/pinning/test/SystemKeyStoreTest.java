package org.thoughtcrime.ssl.pinning.test;


import org.thoughtcrime.ssl.pinning.SystemKeyStore;

import android.test.AndroidTestCase;

public class SystemKeyStoreTest extends AndroidTestCase {

  public void testConstruction() {
        assertNotNull(SystemKeyStore.getInstance());
  }

}
