
class Iso8601Duration {
    private years: number = 0;
    private months: number = 0;
    private weeks: number = 0;
    private days: number = 0;
    private hours: number = 0;
    private minutes: number = 0;
    private seconds: number = 0;
    public total_seconds: number = 0;

    private static regex_parse = /^P([\d\.]+Y)?([\d\.]+M)?([\d\.]+W)?([\d\.]+D)?(T([\d\.]+H)?([\d\.]+M)?([\d\.]+S)?)?$/i
    private static regex_validate = /^P([\d\.]+[YMWD]|T[\d\.]+[HMS])/i

    private static regex_gitlab_years = /^(\d*\.?\d+)y(ears?)?$/gi
    private static regex_gitlab_months = /^(\d*\.?\d+)mo(nths?)?$/gi
    private static regex_gitlab_weeks = /^(\d*\.?\d+)w(eeks?)?$/gi
    private static regex_gitlab_days = /^(\d*\.?\d+)(d(ays?)?)?$/gi
    private static regex_gitlab_hours = /^(\d*\.?\d+)h(ours?)?$/gi
    private static regex_gitlab_minutes = /^(\d*\.?\d+)m(inutes?)?$/gi

    constructor(input: string | undefined) {
        if(typeof input !== 'string') {}
        else if(input.startsWith('P')) {
            this.parseIso8601(input);
        } else {
            this.parseGitlabLike(input);
        }
        this.compute_total_seconds();
    }

    parseIso8601(input: string) {
        if(typeof input !== 'string') {
            throw new Error('Input must be a string');
        }
        let matches = input.match(Iso8601Duration.regex_parse);
        if(matches === null) {
            throw new Error('Invalid ISO 8601 duration');
        }
        if(!Iso8601Duration.regex_validate.test(input)) {
            throw new Error('Invalid ISO 8601 duration');
        }
        this.years = parseFloat(matches[1]) || 0;
        this.months = parseFloat(matches[2]) || 0;
        this.weeks = parseFloat(matches[3]) || 0;
        this.days = parseFloat(matches[4]) || 0;
        this.hours = parseFloat(matches[6]) || 0;
        this.minutes = parseFloat(matches[7]) || 0;
        this.seconds = parseFloat(matches[8]) || 0;
    }

    parseGitlabLike(input: string) {
        if(typeof input !== 'string') {
            throw new Error('Input must be a string');
        }
        let blocks = input.trim().split(' ');
        for(let block of blocks) {
            let matches;
            if((matches = block.match(Iso8601Duration.regex_gitlab_years)) !== null) {
                this.years += parseFloat(matches[0]) || 0;
            } else if((matches = block.match(Iso8601Duration.regex_gitlab_months)) !== null) {
                this.months += parseFloat(matches[0]) || 0;
            } else if((matches = block.match(Iso8601Duration.regex_gitlab_weeks)) !== null) {
                this.weeks += parseFloat(matches[0]) || 0;
            } else if((matches = block.match(Iso8601Duration.regex_gitlab_days)) !== null) {
                this.days += parseFloat(matches[0]) || 0;
            } else if((matches = block.match(Iso8601Duration.regex_gitlab_hours)) !== null) {
                this.hours += parseFloat(matches[0]) || 0;
            } else if((matches = block.match(Iso8601Duration.regex_gitlab_minutes)) !== null) {
                let found_m = parseFloat(matches[0]) || 0;
                if (found_m <= 4) {
                    this.months += found_m; // 4m is more likely to be 4 months than 4 minutes
                } else {
                    this.minutes += found_m;
                }
            } else {
                console.warn('Invalid part in Gitlab-like notation:', block);
            }
        }
    }

    private compute_total_seconds() {
        this.total_seconds = this.seconds;
        this.total_seconds += this.minutes * 60;
        this.total_seconds += this.hours * 3600;
        this.total_seconds += this.days * 28800;
        this.total_seconds += this.weeks * 144000;
        this.total_seconds += this.months * 576000;
        this.total_seconds += this.years * 6912000;
    }

    formatAsIso8601() {
        let output = 'P';
        if(this.years) output += this.years + 'Y';
        if(this.months) output += this.months + 'M';
        if(this.weeks) output += this.weeks + 'W';
        if(this.days) output += this.days + 'D';
        if(this.hours || this.minutes || this.seconds) {
            output += 'T';
            if(this.hours) output += this.hours + 'H';
            if(this.minutes) output += this.minutes + 'M';
            if(this.seconds) output += this.seconds + 'S';
        }
        if(output === 'P') output += '0D';
        return output;
    }

    formatHumanShort() {
        let output = '';
        if(this.years) output += this.years + 'y ';
        if(this.months) output += this.months + 'mo ';
        if(this.weeks) output += this.weeks + 'w ';
        if(this.days) output += this.days + 'd ';
        if(this.hours) output += this.hours + 'h ';
        if(this.minutes) output += this.minutes + 'm ';
        if(output === '') output = 'N/A';
        return output.trim();
    }

}

export default Iso8601Duration;
