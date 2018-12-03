import { Component, OnInit } from '@angular/core';
import {FormBuilder, FormGroup, Validators} from '@angular/forms';
import {Router} from '@angular/router';
import {UserService} from '../../Services/user.service';
import {AlertService} from '../../Services/alert.service';
import {first} from 'rxjs/operators';
import { of, Observable } from 'rxjs';
@Component({
  selector: 'app-password-change',
  templateUrl: './password-change.component.html',
  styleUrls: ['./password-change.component.css']
})
export class PasswordChangeComponent implements OnInit {
  changePasswordForm: FormGroup;
  loading = false;
  submitted = false;
  showMessage = false;
  isSaveSuccess = false;
  message: string;
  constructor(private formBuilder: FormBuilder,
              private router: Router,
              private userService: UserService,
              private alertService: AlertService) {  }

  ngOnInit() {
    this.changePasswordForm = this.formBuilder.group({
      oldPassword: ['', Validators.compose([Validators.required, Validators.minLength(6)])],
      newPassword: ['', Validators.compose([Validators.required, Validators.minLength(6)])],
      confirmPassword: ['', Validators.required]
    }, {validator: this.checkPasswords });
  }
  get f() { return this.changePasswordForm.controls; }
  checkPasswords(group: FormGroup) {
    const password = group.controls.newPassword.value;
    const confirmPassword = group.controls.confirmPassword.value;
    return password === confirmPassword ? null : { notSame: true };
  }
  onSubmit() {
    this.submitted = true;
    // stop here if form is invalid
    if (this.changePasswordForm.invalid) {
      return;
    }

    this.loading = true;
    const user = JSON.parse(localStorage.getItem('currentUser'));
    this.userService.update(user.id, this.changePasswordForm.controls.oldPassword.value, this.changePasswordForm.controls.newPassword.value)
      .pipe(first())
      .subscribe(
        data => {
          console.log(data);
          if (data['Success']) {
            this.isSaveSuccess = true;
            this.message = data['Success'];
          } else if (data['Error']) {
            this.isSaveSuccess = false;
            this.message = data['Error'];
          }
          this.showMessage = true;
          this.loading = false;
        },
        error => {
          this.alertService.error(error);
          if (error.status = 403) {
            this.router.navigate(['/login']);
          }
          this.loading = false;
        });

  }
}
