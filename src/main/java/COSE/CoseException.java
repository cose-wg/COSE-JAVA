/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package COSE;

/**
 *
 * @author jimsch
 */
public class CoseException extends Exception {
    public CoseException(String message) {
        super(message);
    }
    public CoseException(String message, Exception ex) {
        super(message, ex);
    }
}
