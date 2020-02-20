var Cvss_v2 = function (id, options) {
    this.options = options;
    this.wId = id;
    var e = function (tag) {
        return document.createElement(tag);
    };

    // Base Group
    this.bg = {
        AV: 'Attack Vector',
        AC: 'Attack Complexity',
        AU: 'Authentication',
        C: 'Confidentiality',
        I: 'Integrity',
        A: 'Availability'
    };

    // Base Metrics
    this.bm = {
        AV: {
            N: {
                l: 'Network',
            },
            A: {
                l: 'Adjacent',
            },
            L: {
                l: 'Local',
            }
        },
        AC: {
            L: {
                l: 'Low',
            },
            M: {
                l: 'Medium'
            },
            H: {
                l: 'High',
            }
        },
        AU: {
            N: {
                l: 'None',
            },
            S: {
                l: 'Single',
            },
            M: {
                l: 'Multiple',
            }
        },
        C: {
            C: {
                l: 'Complete',
            },
            P: {
                l: 'Patial',
            },
            N: {
                l: 'None',
            }
        },
        I: {
            C: {
                l: 'Complete',
            },
            P: {
                l: 'Patial',
            },
            N: {
                l: 'None',
            }
        },
        A: {
            C: {
                l: 'Complete',
            },
            P: {
                l: 'Patial',
            },
            N: {
                l: 'None',
            }
        }
    };

    this.bme = {};
    this.bmgReg = {
        AV: 'NAL',
        AC: 'LMH',
        AU: 'NSM',
        C: 'MPN',
        I: 'MPN',
        A: 'MPN'
    };
    this.bmoReg = {
        AV: 'NAL',
        AC: 'LMH',
        C: 'C',
        I: 'C',
        A: 'C'
    };
    var s, f, dl, g, dd, l;
    this.el = document.getElementById(id);
    this.el.appendChild(s = e('style'));
    s.innerHTML = '';
    this.el.appendChild(f = e('form'));
    f.className = 'cvssjs';
    this.calc = f;
    for (g in this.bg) {
        f.appendChild(dl = e('dl'));
        dl.setAttribute('class', g);
        var dt = e('dt');
        dt.innerHTML = this.bg[g];
        dl.appendChild(dt);
        for (s in this.bm[g]) {
            dd = e('dd');
            dl.appendChild(dd);
            var inp = e('input');
            inp.setAttribute('name', g);
            inp.setAttribute('value', s);
            inp.setAttribute('id', id + g + s);
            inp.setAttribute('class', g + s);
            inp.setAttribute('type', 'radio');
            this.bme[g + s] = inp;
            var me = this;
            inp.onchange = function () {
                me.setMetric(this);
            };
            dd.appendChild(inp);
            l = e('label');
            dd.appendChild(l);
            l.setAttribute('for', id + g + s);
            l.appendChild(e('i')).setAttribute('class', g + s);
            l.appendChild(document.createTextNode(this.bm[g][s].l + ' '));
            dd.appendChild(e('small')).innerHTML = this.bm[g][s].d;
        }
    }
    //f.appendChild(e('hr'));
    f.appendChild(dl = e('dl'));
    dl.innerHTML = '<dt>Severity&sdot;Score&sdot;Vector</dt>';
    dd = e('dd');
    dl.appendChild(dd);
    l = dd.appendChild(e('label'));
    l.className = 'results';
    l.appendChild(this.severity = e('span'));
    this.severity.className = 'severity';
    l.appendChild(this.score = e('span'));
    this.score.className = 'score';
    l.appendChild(document.createTextNode(' '));
    l.appendChild(this.vector = e('a'));
    this.vector.className = 'vector';
    this.vector.innerHTML = 'Cvss_v2:2.0/AV:_/AC:_/AU:_/C:_/I:_/A:_';

    if (options.onsubmit) {
        f.appendChild(e('hr'));
        this.submitButton = f.appendChild(e('input'));
        this.submitButton.setAttribute('type', 'submit');
        this.submitButton.onclick = options.onsubmit;
    }
};

Cvss_v2.prototype.severityRatings = [{
    name: "None",
    bottom: 0.0,
    top: 0.0
}, {
    name: "Low",
    bottom: 0.1,
    top: 3.9
}, {
    name: "Medium",
    bottom: 4.0,
    top: 6.9
}, {
    name: "High",
    bottom: 7.0,
    top: 8.9
}, {
    name: "Critical",
    bottom: 9.0,
    top: 10.0
}];

Cvss_v2.prototype.valueofradio = function (e) {
    for (var i = 0; i < e.length; i++) {
        if (e[i].checked) {
            return e[i].value;
        }
    }
    return null;
};

Cvss_v2.prototype.calculate = function () {
    var cvssVersion = "2.0";

    var Weight = {
        AV: {
            N: 1.0,
            A: 0.646,
            L: 0.395,

        },
        AC: {
            H: 0.35,
            M: 0.61,
            L: 0.71
        },
        AU: {
            N: 0.704,
            S: 0.56,
            M: 0.45
        },
        C: {
            N: 0,
            P: 0.275,
            C: 0.66
        },
        I: {
            N: 0,
            P: 0.275,
            C: 0.66
        },
        A: {
            N: 0,
            P: 0.275,
            C: 0.66
        }
    };

    var p;
    var val = {}, metricWeight = {};
    try {
        for (p in this.bg) {
            val[p] = this.valueofradio(this.calc.elements[p]);
            if (typeof val[p] === "undefined" || val[p] === null) {
                return "?";
            }
            metricWeight[p] = Weight[p][val[p]];
        }
    } catch (err) {
        return err;
    }

    var impactSubScore = 10.41 * (1 - ((1 - metricWeight.C) * (1 - metricWeight.I) * (1 - metricWeight.A)));
    var exploitabalitySubScore = 20 * metricWeight.AV * metricWeight.AC * metricWeight.AU;
    var baseScore = ((0.6 * impactSubScore) + (0.4 * exploitabalitySubScore) - 1.5) * 1.176;
    baseScore = Math.ceil(baseScore * 10) / 10;
    console.log(baseScore);

    return baseScore-1.0;

};

Cvss_v2.prototype.get = function () {
    return {
        score: this.score.innerHTML,
        vector: this.vector.innerHTML
    };
};

Cvss_v2.prototype.setMetric = function (a) {
    var vectorString = this.vector.innerHTML;
    if (/AV:.\/AC:.\/AU:.\/C:.\/I:.\/A:./.test(vectorString)) {
    } else {
        vectorString = 'AV:_/AC:_/AU:_/C:_/I:_/A:_';
    }
    //e("E" + a.id).checked = true;
    var newVec = vectorString.replace(new RegExp('\\b' + a.name + ':.'), a.name + ':' + a.value);
    this.set(newVec);
};

Cvss_v2.prototype.set = function (vec) {
    var newVec = 'Cvss_v2:2.0/';
    var sep = '';
    for (var m in this.bm) {
        var match = (new RegExp('\\b(' + m + ':[' + this.bmgReg[m] + '])')).exec(vec);
        if (match !== null) {
            var check = match[0].replace(':', '');
            this.bme[check].checked = true;
            newVec = newVec + sep + match[0];
        } else if ((m in {C: '', I: '', A: ''}) && (match = (new RegExp('\\b(' + m + ':C)')).exec(vec)) !== null) {
            // compatibility with v2 only for CIA:C
            //this.bme[m + 'H'].checked = true;
            newVec = newVec + sep + m + ':H';
        } else {
            newVec = newVec + sep + m + ':_';
            for (var j in this.bm[m]) {
                this.bme[m + j].checked = false;
            }
        }
        sep = '/';
    }
    this.update(newVec);
};

Cvss_v2.prototype.update = function (newVec) {
    this.vector.innerHTML = newVec;
    var s = this.calculate();
    //console.log(s);
    this.score.innerHTML = s;
    if (this.options !== undefined && this.options.onchange !== undefined) {
        this.options.onchange();
    }
};