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
public enum MessageTag {
    Unknown(0),
    Encrypt0(993),
    Encrypt(992),
    Sign1(997),
    Sign(991),
    MAC(994),
    MAC0(996);
    
    public final int value;
    
    MessageTag(int i) {
        value = i;
    }
    
    public static MessageTag FromInt(int i) throws CoseException {
        for (MessageTag m : MessageTag.values()) {
            if (i == m.value) return m;
        }
        throw new CoseException("Not a message tag number");
    }
}
