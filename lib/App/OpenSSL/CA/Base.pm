use Object::Pad ':experimental(:all)';

package App::OpenSSL::CA::Base;
role App::OpenSSL::CA::Base;

use utf8;
use v5.40;

<<<<<<< HEAD
ADJUSTPARAMS($params) {
=======
use Time::HiRes ();
>>>>>>> cc85d17 (...)

method epoch : common ($join = '') {
    join $join, Time::HiRes::gettimeofday;
}
<<<<<<< HEAD

#method test : common (%opts);

=======
>>>>>>> cc85d17 (...)
