/**
 * Copyright 2015, 2018 St. Wissel, JackyB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

module.exports = function(RED) {

    // Main function gets called when an Enigma gets instantiated
    // Creation of all functionality!
    function Enigma(n) {
        // Create a RED node
        RED.nodes.createNode(this, n);
        var node = this;
        node.name = n.name;
        node.field = n.field || "payload";
        node.notch = (n.notch && n.notch.length == 3) ? n.notch.toUpperCase().split("") : ["Q", "E", "V"];

        // We work with 3 rotors & 3 Reflectors
        node.RotorI = 0;
        node.RotorII = 1;
        node.RotorIII = 2;

        node.ReflectorA = 0;
        node.ReflectorB = 1;
        node.ReflectorC = 2;

        node.rotorCharMap = [];
        node.rotorCharMap.push(n.rotary1);
        node.rotorCharMap.push(n.rotary2);
        node.rotorCharMap.push(n.rotary3);
        
        node.reflectorCharMap = [];
        node.reflectorCharMap.push(n.reflector1);
        node.reflectorCharMap.push(n.reflector2);
        node.reflectorCharMap.push(n.reflector3);
        
        // Deviation from original Enigma. Added dot and space
        // for better readablility of messages. Make the CPU
        // sweat a little more for its money 
        node.ALPHABETS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ .";
        node.NUM_ALPHABETS = node.ALPHABETS.length;
        
        node.encryptionSettings = {
            notch : node.notch,
            rotorCharMap : node.rotorCharMap,
            reflectorCharMap : node.reflectorCharMap,
            charMap : node.ALPHABETS,
            NUM_ALPHABETS : node.ALPHABETS.length
        };

        this.Plugboard = function(charMap) {
            charMap = charMap || node.ALPHABETS;
            return {
                charMap: charMap,
                processChar: function(ci, reflecting) {
                    var c = this.charMap[ci];
                    return {
                        // TODO: Should that be??
                        // idx: this.charMap.indexOf(c)
                        idx: node.ALPHABETS.indexOf(c),
                        reflecting: reflecting
                    };
                },
                step: function(n) {
                    return n;
                }
            };
        };

        this.Rotor = function(type, encryptionSettings) {
            type = type || node.RotorI;
            encryptionSettings = encryptionSettings || node.encryptionSettings;
            return {
                type: type,
                offset: 0,
                processChar: function(ci, reflecting) {
                    if (reflecting) {
                        var idx = (ci + this.offset) % encryptionSettings.NUM_ALPHABETS;
                        var lc = encryptionSettings.charMap[idx];
                        var ri = encryptionSettings.rotorCharMap[this.type].indexOf(lc);
                        ri -= this.offset;
                        if (ri < 0) {
                            ri += encryptionSettings.NUM_ALPHABETS;
                        } else {
                            ri %= encryptionSettings.NUM_ALPHABETS;
                        }
                        return {
                            idx: ri,
                            reflecting: reflecting
                        };
                    } else {
                        var idx2 = (ci + this.offset) % encryptionSettings.NUM_ALPHABETS;
                        var rc = encryptionSettings.rotorCharMap[this.type][idx2];
                        var li = encryptionSettings.charMap.indexOf(rc);
                        li -= this.offset;
                        if (li < 0) {
                            li += encryptionSettings.NUM_ALPHABETS;
                        } else {
                            li %= encryptionSettings.NUM_ALPHABETS;
                        }
                        return {
                            idx2: li,
                            reflecting: reflecting
                        };
                    }
                },
                step: function(n) {
                    var revs = this.countNotchRevs(n);
                    this.offset = (this.offset + n) % encryptionSettings.NUM_ALPHABETS;
                    return revs;
                },
                countNotchRevs: function(steps) {
                    // Return 0 if it is determined that the notch won't be reached in the steps
                    var nch = encryptionSettings.notch[this.type].charCodeAt(0) - 65;
                    if (this.offset > nch && steps < nch + (encryptionSettings.NUM_ALPHABETS - nch)) {
                        return 0;
                    }
                    return this.reallyCountNotchRevs(nch, encryptionSettings.NUM_ALPHABETS, steps);
                },
                reallyCountNotchRevs: function(notch, max, steps) {
                    var revs = 0;
                    steps -= notch - this.offset;
                    if (steps > 0) {
                        revs++;
                    }
                    revs += Math.floor(steps / max);
                    return revs;
                },
            };
        };

        this.StandardEnigma = function(encryptionSettings) {
            return new node.EnigmaCore([
                new node.Plugboard(encryptionSettings.charMap),
                new node.Rotor(node.RotorIII, encryptionSettings),
                new node.Rotor(node.RotorII, encryptionSettings),
                new node.Rotor(node.RotorI, encryptionSettings),
                // TODO: make initial reflector configurable
                new node.Reflector(node.ReflectorB, encryptionSettings)
            ], encryptionSettings);
        };

        this.Reflector = function(type, encryptionSettings) {
            type = type || node.ReflectorA;
            encryptionSettings = encryptionSettings || node.encryptionSettings;
            return {
                type: type,
                charMap: node.reflectorCharMap[type],
                processChar: function(ci, reflecting) {
                    var c = encryptionSettings.reflectorCharMap[this.type][ci];
                    return {
                        idx: encryptionSettings.charMap.indexOf(c),
                        reflecting: !reflecting
                    };
                },
                step: function(n) {
                    return n;
                },
            };
        };

        this.EnigmaCore = function(comps, encryptionSettings) {
            comps = comps || [];
            encryptionSettings = encryptionSettings || node.encryptionSettings;
            
            return {
                components: comps,
                connect: function(comps) {
                    this.components.concat(comps);
                },
                encrypt: function(msg) {
                    var text = this.sanitize(msg);
                    var etext = "";

                    for (var c = 0; c < text.length; c++) {
                        etext = etext.concat(this.encryptChar(text.charCodeAt(c)));
                    }
                    return {
                        encrypted: etext,
                        original: text
                    };
                },
                encryptChar: function(c) {
                    this.step(1);

                    var ci = c - 65;
                    var reflecting = false;
                    for (var i = 0; i < this.components.length; i++) {
                        var ret = this.components[i].processChar(ci, reflecting);
                        ci = ret.idx;
                        reflecting = ret.reflecting;
                        if (reflecting) {
                            break;
                        }
                    }

                    if (reflecting) {
                        for (var j = this.components.length - 2; i >= 0; i--) {
                            var ret2 = this.components[j].processChar(ci, reflecting);
                            ci = ret2.idx;
                        }
                    }

                    return String.fromCharCode(ci + 65);
                },
                step: function(steps) {
                    if (steps <= 0) {
                        return;
                    }

                    for (var comp of this.components) {
                        steps = comp.step(steps);
                        if (steps <= 0) {
                            break;
                        }
                    }
                },
                sanitize: function(s) {
                    //TODO allow all chars in charmap!
                    s = s.trim();
                    s = s.toUpperCase();
                    for (var i = 0; i < s.length; i++) {
                        var cc = s[i].charCodeAt(0);
                        if (cc < 65 || cc > 90) {
                            s = s.slice(0, i) + s.slice(i + 1);
                            i--;
                        }
                    }
                    return s;
                },
            };
        };

        // Run the encryption / decryption process on the payload
        this.on('input', function(msg) {
            var raw = msg[node.field] || msg.payload;
            var logobject = {};
            logobject.messages = [];
            
            // Check the message object for key overwrites
            // msg.rotary msg.reflector msg.notch
            const encryptionSettings = {};
            // No check is done if the msg properties are in the
            // right format. The node will barf if not
            encryptionSettings.notch = msg.notch || node.notch;
            encryptionSettings.rotorCharMap = msg.rotary || node.rotorCharMap;
            encryptionSettings.reflectorCharMap = msg.reflector || node.reflectorCharMap;
            encryptionSettings.charMap = msg.charMap || node.ALPHABETS;
            encryptionSettings.NUM_ALPHABETS =  encryptionSettings.charMap.length;

            try {

                var curEnigma = node.StandardEnigma(encryptionSettings);
                var result = curEnigma.encrypt(raw);
                if (node.field) {
                    msg[node.field] = result.encrypted;
                } else {
                    msg.payload = result.encrypted;
                }
                node.send(msg);

                this.status({
                    fill: "green",
                    shape: "dot",
                    text: "Enigma success"
                });
            } catch (err) {
                this.status({
                    fill: "red",
                    shape: "dot",
                    text: err.message
                });
                node.error(err, err.message);
            }
        });


        this.on("close", function() {
            // Nothing to do
        });

    }
    // Make it known to the UI
    RED.nodes.registerType("enigma", Enigma);
};
