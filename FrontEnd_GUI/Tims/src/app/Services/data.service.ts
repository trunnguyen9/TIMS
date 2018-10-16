import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class DataService {
  constructor() { }
  private loginStatus = new BehaviorSubject<boolean>(false);
  currentLoginStatus = this.loginStatus.asObservable();

  changeLoginStatus(isLogin: boolean) {
    this.loginStatus.next(isLogin);
  }
}
