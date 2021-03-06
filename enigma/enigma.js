/**
 * Copyright 2015 St. Wissel, JackyB
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

        //TODO: Read charmaps from config
        node.rotorCharMap = [
            "EKMFLGDQVZNTOWYHXUSPAIBRCJ",
            "AJDKSIRUXBLHWTMCQGZNPYFVOE",
            "BDFHJLCPRTXVZNYEIWGAKMUSQO"
        ];

        node.reflectorCharMap = [
            "EJMZALYXVBWFCRQUONTSPIKHGD",
            "YRUHQSLDPXNGOKMIEBFZCWVJAT",
            "FVPJIAOYEDRZXWGCTKUQSBNMHL"
        ];

        node.ALPHABETS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            node.NUM_ALPHABETS = 26;

        this.Plugboard = function(charMap) {
            charMap = typeof charMap == "undefined" ? node.ALPHABETS : charMap;
            return {
                charMap: charMap,
                processChar: function(ci, reflecting) {
                    var c = this.charMap[ci];
                    return {
                        idx: node.ALPHABETS.indexOf(c),
                        reflecting: reflecting
                    };
                },
                step: function(n) {
                    return n;
                }
            };
        };

        this.Rotor = function(type) {
            type = typeof type == "undefined" ? node.RotorI : type;
            return {
                type: type,
                offset: 0,
                processChar: function(ci, reflecting) {
                    if (reflecting) {
                        var idx = (ci + this.offset) % node.NUM_ALPHABETS;
                        var lc = node.ALPHABETS[idx];
                        var ri = node.rotorCharMap[this.type].indexOf(lc);
                        ri -= this.offset;
                        if (ri < 0) {
                            ri += node.NUM_ALPHABETS;
                        } else {
                            ri %= node.NUM_ALPHABETS;
                        }
                        return {
                            idx: ri,
                            reflecting: reflecting
                        };
                    } else {
                        var idx = (ci + this.offset) % node.NUM_ALPHABETS;
                        var rc = node.rotorCharMap[this.type][idx];
                        var li = node.ALPHABETS.indexOf(rc);
                        li -= this.offset;
                        if (li < 0) {
                            li += node.NUM_ALPHABETS;
                        } else {
                            li %= node.NUM_ALPHABETS;
                        }
                        return {
                            idx: li,
                            reflecting: reflecting
                        };
                    }
                },
                step: function(n) {
                    var revs = this.countNotchRevs(n);
                    this.offset = (this.offset + n) % node.NUM_ALPHABETS;
                    return revs;
                },
                countNotchRevs: function(steps) {
                    // Return 0 if it is determined that the notch won't be reached in the steps
                    var nch = node.notch[this.type].charCodeAt(0) - 65;
                    if (this.offset > nch && steps < nch + (node.NUM_ALPHABETS - nch)) {
                        return 0;
                    }
                    return this.reallyCountNotchRevs(nch, node.NUM_ALPHABETS, steps);
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

        this.StandardEnigma = function() {
            return new node.EnigmaCore([
                new node.Plugboard(),
                new node.Rotor(node.RotorIII),
                new node.Rotor(node.RotorII),
                new node.Rotor(node.RotorI),
                new node.Reflector(node.ReflectorB),
            ]);
        };

        this.Reflector = function(type) {
            type = typeof type == "undefined" ? node.ReflectorA : type;
            return {
                type: type,
                charMap: node.reflectorCharMap[type],
                processChar: function(ci, reflecting) {
                    var c = node.reflectorCharMap[this.type][ci];
                    return {
                        idx: node.ALPHABETS.indexOf(c),
                        reflecting: !reflecting
                    };
                },
                step: function(n) {
                    return n;
                },
            };
        };

        this.EnigmaCore = function(comps) {
            comps = typeof comps == "undefined" ? [] : comps;
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
                        for (var i = this.components.length - 2; i >= 0; i--) {
                            var ret = this.components[i].processChar(ci, reflecting);
                            ci = ret.idx;
                        }
                    }

                    return String.fromCharCode(ci + 65);
                },
                step: function(steps) {
                    if (steps <= 0) {
                        return;
                    }

                    for (var comp of this.components) {
                        steps = comp.step(steps)
                        if (steps <= 0) {
                            break;
                        }
                    }
                },
                sanitize: function(s) {
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
        }

        // Run the encryption / decryption process on the payload
        this.on('input', function(msg) {
            var raw = msg[node.field] || msg.payload;
            var logobject = {};
            logobject.messages = [];

            try {

                var curEnigma = node.StandardEnigma();
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
                node.error(err.message);
            }
        });


        this.on("close", function() {
            // Nothing to do
        });

    }
    // Make it known to the UI
    RED.nodes.registerType("enigma", Enigma);
}
