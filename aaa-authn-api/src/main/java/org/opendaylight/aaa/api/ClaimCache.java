/*
 * Copyright (c) 2018 Inocybe Technologies and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
package org.opendaylight.aaa.api;

/**
 * Interface for a class that caches active {@link Claim}s.
 *
 * @author Thomas Pantelis
 */
public interface ClaimCache {

    /**
     * Clears the cache of any active claims.
     */
    void clear();
}
