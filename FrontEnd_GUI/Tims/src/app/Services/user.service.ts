import { Injectable } from '@angular/core';
import {User} from '../Model/user';
import { HttpClient } from '@angular/common/http';

@Injectable({
  providedIn: 'root'
})
export class UserService {

  constructor(private http: HttpClient) { }

  register(user: User) {
    console.log(user);
    return this.http.post('http://127.0.0.1:5000/users/register', user);
  }

  update(user: User) {
    return this.http.put('/users' + user.id, user);
  }

  delete(id: number) {
    return this.http.delete('/users' + id);
  }
}
