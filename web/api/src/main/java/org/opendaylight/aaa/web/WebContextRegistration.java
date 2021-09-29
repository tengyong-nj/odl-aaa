/*
 * Copyright (c) 2018 Red Hat, Inc. and others. All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */
package org.opendaylight.aaa.web;

/**
 * {@link WebContext} registration.
 * Allows to {@link #close()} the web context, which unregisters its servlets, filters and listeners.
 *
 * @author Michael Vorburger.ch
 */
public interface WebContextRegistration extends AutoCloseable {

    @Override
    void close(); // does not throw Exception

}
