import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class DataService {
  constructor() { }
  private loginStatus = new BehaviorSubject<boolean>(this.isLogin());
  currentLoginStatus = this.loginStatus.asObservable();

  changeLoginStatus(isLogin: boolean) {
    this.loginStatus.next(isLogin);
  }

  isLogin() {
    if (localStorage.getItem('currentUser')) {
      return true;
    }
    return false;
  }
}
