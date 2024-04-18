/*
 * XMLRSS - A Java Crypto Provider for Redactable Signatures and their
 * XML Signature encoding.
 *
 * Copyright (c) 2016 Wolfgang Popp
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package de.unipassau.wolfgangpopp.xmlrss.wpprovider;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;

/**
 * The <code>WPProvider</code> (shamelessly named after myself) is a cryptographic service provider that implements
 * redactable signatures, redactable XML signatures, and cryptographic accumulators.
 *
 * @author Wolfgang Popp
 */
public class WPProvider extends Provider {

    public WPProvider() {
        super("WP", 0.1, "WP Provider (implements Redactable Signature Schemes, Accumulators)");
        AccessController.doPrivileged(new PrivilegedAction<Object>() {
            public Object run() {
                setup();
                return null;
            }
        });
    }

    private void setup() {
        // Redactable signature engines
        put("RedactableSignature.RSSwithPSAccumulator",
                "de.unipassau.wolfgangpopp.xmlrss.wpprovider.psrss.PSRedactableSignature$PSRSSwithPSA");
        put("Alg.Alias.RedactableSignature.RSSwithACC", "RSSwithPSAccumulator");
        put("Alg.Alias.RedactableSignature.RSSwithPSA", "RSSwithPSAccumulator");
        put("Alg.Alias.RedactableSignature.PSRSSwithPSA", "RSSwithPSAccumulator");

        put("RedactableSignature.GSRSSwithRSAandBPA",
                "de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.GSRedactableSignature$GSRSSwithBPAccumulatorAndRSA");

        put("RedactableSignature.GLRSSwithRSAandBPA",
                "de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.GLRedactableSignature$GLRSSwithBPAccumulatorAndRSA");


        // Redactable XML signature engines
        put("RedactableXMLSignature.XMLPSRSSwithPSA",
                "de.unipassau.wolfgangpopp.xmlrss.wpprovider.psrss.PSRedactableXMLSignature$XMLPSRSSwithPSA");
        put("Alg.Alias.RedactableXMLSignature.PSRSSwithPSA", "XMLPSRSSwithPSA");
        put("RedactableXMLSignature.GSRSSwithRSAandBPA",
                "de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.xml.GSRedactableXMLSignature$GSRSSwithBPAccumulatorAndRSA");
        put("RedactableXMLSignature.GLRSSwithRSAandBPA",
                "de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.xml.GLRedactableXMLSignature$GLRSSwithBPAccumulatorAndRSA");

        // Key pair generator engines
        put("KeyPairGenerator.PSRSS", "de.unipassau.wolfgangpopp.xmlrss.wpprovider.psrss.PSRSSKeyPairGenerator");
        put("KeyPairGenerator.BPA", "de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.BPKeyPairGenerator");
        put("KeyPairGenerator.GSRSSwithRSAandBPA",
                "de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.GSRSSKeyPairGenerator$GSRSSwithRSAandBPA");
        put("KeyPairGenerator.GLRSSwithRSAandBPA",
                "de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.GLRSSKeyPairGenerator$GLRSSwithRSAandBPA");

        // Accumulator engines
        put("Accumulator.PSA", "de.unipassau.wolfgangpopp.xmlrss.wpprovider.psrss.PSAccumulator");
        put("Accumulator.BPA", "de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.BPAccumulator");
    }
}
